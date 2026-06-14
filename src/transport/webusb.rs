// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebUSB transport for Passport Prime hardware.
//!
//! Vaults Bridge registers a vendor-class USB interface with a pair of
//! 64-byte Interrupt endpoints and two Platform Capability descriptors
//! (WebUSB and Microsoft OS 2.0). The browser extension reaches it via
//! Chromium's WebUSB API (`navigator.usb`).
//!
//! Wire format: newline-delimited JSON. Each request / response is a full
//! `serde_json::to_vec`'d object followed by a single `\n` byte, chunked
//! into 64-byte transfers across the endpoints. The extension accumulates
//! across `transferIn` results until it sees `\n`.
//!
//! Mirrors the structure of `gui-app-nostr-signer/src/transport/webusb.rs`
//! on the `qna/nostr-signer-1.3` branch so a single set of `os/usbdev`
//! facilities is exercised the same way by both apps.

use std::sync::{mpsc, Arc};
use std::time::{SystemTime, UNIX_EPOCH};

use server::{BlockingArchiveHandler, Server, ServerContext, ServerMessages};
use usb::device::{
    api::{EndpointDirection, EndpointType},
    messages::{EndpointProperties, SetupPacketCallback},
};
use vaults_bridge_core::engine::Engine;
use vaults_bridge_keystore::Keystore;
use vaults_bridge_protocol::{ErrorCode, ErrorPayload, Request, Response};

usb::use_device_api!();

// --- USB descriptors --------------------------------------------------------

const WEBUSB_IFCE_CLASS: u8 = 0xFF;
const WEBUSB_IFCE_SUBCLASS: u8 = 0xFF;
const WEBUSB_IFCE_PROTOCOL: u8 = 0xFF;
const WEBUSB_INTERFACE_NUMBER: u8 = 0;

/// Hard cap on a single newline-delimited request, in bytes. Matches
/// `vaults_bridge_protocol::frame::LineSplitter::MAX_LINE_BYTES`. A host
/// that sends more without ever emitting `\n` is faulty or hostile; we
/// drop the in-progress line and continue.
const MAX_LINE_BYTES: usize = 16 * 1024;

/// Vendor code embedded in the WebUSB Platform Capability descriptor.
/// Distinct from nostr-signer 1.3's 0x1E so a future build that runs both
/// apps on the same firmware doesn't get its setup responders confused;
/// in practice KeyOS is one-foreground-app so this is belt-and-suspenders.
const WEBUSB_VENDOR_CODE: u8 = 0x1F;

/// 64-byte Interrupt endpoints, interval = 1 (1ms service interval).
/// `use_dma: false` so we route through the PIO path. Runtime-registered
/// second interfaces land on EPs 8-15 (no DMA slot) and the PIO fix
/// from SUP-1243 makes that path stable; DMA is reserved for the boot
/// CDC log + FIDO.
const WEBUSB_ENDPOINTS: [EndpointProperties; 2] = [
    EndpointProperties {
        ep_type: EndpointType::Interrupt,
        ep_direction: EndpointDirection::In,
        max_packet_len: 64,
        interval: 1,
        use_dma: false,
    },
    EndpointProperties {
        ep_type: EndpointType::Interrupt,
        ep_direction: EndpointDirection::Out,
        max_packet_len: 64,
        interval: 1,
        use_dma: false,
    },
];

// --- Setup responder -------------------------------------------------------

/// Responds to WebUSB's vendor control request for the URL descriptor.
/// We have no landing page (`iLandingPage = 0`), so the URL descriptor
/// is empty. Hosts that probe still get a clean 3-byte response rather
/// than a STALL that shows up as an error in system logs.
#[derive(Default)]
struct SetupResponder;

impl ServerMessages for SetupResponder {
    const NAME: &'static str = "";

    fn messages() -> &'static [server::MessageDef<Self>] {
        use server::MessageId;
        &[(SetupPacketCallback::ID, server::handle_blocking_archive_message::<SetupPacketCallback, _>)]
    }
}
impl Server for SetupResponder {}

impl BlockingArchiveHandler<SetupPacketCallback> for SetupResponder {
    fn handle(
        &mut self,
        SetupPacketCallback(msg): SetupPacketCallback,
        _sender: xous::PID,
        _ctx: &mut ServerContext<Self>,
    ) -> Option<Vec<u8>> {
        // bmRequestType=0xC0 (vendor, device, IN),
        // bRequest=WEBUSB_VENDOR_CODE,
        // wIndex=2 (URL descriptor index).
        if msg.request_type == 0xc0 && msg.request == WEBUSB_VENDOR_CODE && msg.index == 2 {
            // bLength=3, bDescriptorType=3 (WEBUSB_URL), bScheme=0xff
            // (no scheme prefix), zero URL bytes.
            return Some(vec![3, 3, 0xff]);
        }
        None
    }
}

// --- Transport loop --------------------------------------------------------

pub async fn serve(engine: Arc<Engine<Keystore>>, _unused_bind: &str) -> anyhow::Result<()> {
    serve_blocking(engine)
}

fn serve_blocking(engine: Arc<Engine<Keystore>>) -> anyhow::Result<()> {
    crate::transport::set_status("WebUSB: init");
    let mut usb = UsbDeviceEmulation::default();

    crate::transport::set_status("WebUSB: registering interface");
    let (_webusb_interface, [mut ep_in, ep_out]) = match usb.register_interface(
        UsbInterfaceConfig::new(
            WEBUSB_INTERFACE_NUMBER,
            WEBUSB_IFCE_CLASS,
            WEBUSB_IFCE_SUBCLASS,
            WEBUSB_IFCE_PROTOCOL,
            &WEBUSB_ENDPOINTS,
        )
        // WebUSB Platform Capability descriptor.
        // UUID per https://wicg.github.io/webusb/#webusb-platform-capability-descriptor.
        .with_capability(
            16, // bDescriptorType: DEVICE CAPABILITY
            5,  // bDevCapabilityType: PLATFORM
            uuid::uuid!("3408b638-09a9-47a0-8bfd-a0768815b665"),
            &[
                0x00,
                0x01, // bcdVersion: 1.00
                WEBUSB_VENDOR_CODE,
                0x00, // iLandingPage: 0 (none)
            ],
        )
        // Microsoft OS 2.0 Platform Capability descriptor. Same payload shape
        // nostr-signer 1.3 uses; the descriptor *set* behind the vendor code
        // is a follow-up (Windows auto-bind to WinUSB). On macOS / Linux this
        // is inert.
        .with_capability(
            16,
            5,
            uuid::uuid!("d8dd60df-4589-4cc7-9cd2-659d9e648a9f"),
            &[0x00, 0x00, 0x03, 0x06, 0xb2, 0x00, 0x77, 0x00],
        )
        .with_setup_responder(Some(SetupResponder)),
    ) {
        Ok(interface) => interface,
        Err(e) => {
            let msg = format!("WebUSB: register interface failed: {e:?}");
            log::warn!("{msg}");
            crate::transport::set_status(msg);
            std::thread::park();
            return Ok(());
        }
    };

    let ep_out_num = ep_out.endpoint_number();
    let ep_in_num = ep_in.endpoint_number();
    log::info!("vaults-bridge webusb endpoints registered (out={ep_out_num}, in={ep_in_num})");

    // The app can be opened after the host has already enumerated the base
    // KeyOS USB device. Descriptors registered at runtime are not usable by
    // the host until it re-enumerates, so force a short device-side reset once
    // Vaults Bridge has added its interface.
    crate::transport::set_status("WebUSB: resetting USB");
    usb.reset_controller();

    crate::transport::set_status(format!("WebUSB ready (EP out={ep_out_num}, in={ep_in_num})"));

    let (payload_tx, payload_rx) = mpsc::channel::<Vec<u8>>();

    std::thread::spawn(move || reader_loop(ep_out, ep_out_num, ep_in_num, payload_tx));

    // Dispatcher + writer fused on the same thread. nostr-signer 1.3
    // discovered that the mpsc-over-IPC dispatcher -> writer hop was
    // flaky on Xous even when send returned Ok; serialising response
    // emission inline costs nothing because the protocol is strictly
    // single-flight (one request, one response).
    let usb_api = UsbDeviceEmulation::default();
    let mut write_buf = xous::map_memory(None, None, 0x1000, xous::MemoryFlags::W)
        .map_err(|e| anyhow::anyhow!("webusb map write buf: {e:?}"))?;

    let mut total_handled: u64 = 0;
    while let Ok(payload) = payload_rx.recv() {
        log::trace!("webusb dispatcher: got {} byte payload", payload.len());
        crate::transport::set_status(format!("dispatch {} ({}B)", total_handled + 1, payload.len()));
        let response = slint_keyos_platform::futures_lite::future::block_on(dispatch(&engine, &payload));
        let mut response_bytes = match serde_json::to_vec(&response) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("webusb serialise response: {e}");
                crate::transport::set_status(format!("serialise err: {e}"));
                continue;
            }
        };
        response_bytes.push(b'\n');
        let resp_len = response_bytes.len();
        log::trace!("webusb dispatcher: writing {resp_len} bytes to EP IN");
        crate::transport::set_status(format!("tx {resp_len}B (#{})", total_handled + 1));
        let mut chunk_idx = 0;
        for chunk in response_bytes.chunks(64) {
            chunk_idx += 1;
            write_buf.as_slice_mut::<u8>()[..chunk.len()].copy_from_slice(chunk);
            match ep_in.write_buf(write_buf, chunk.len()) {
                Ok(n) => {
                    crate::transport::set_status(format!("tx chunk {chunk_idx} {}B ok ({n})", chunk.len()));
                }
                Err(usb::error::UsbError::HostDisconnected) => {
                    log::info!("webusb writer: host disconnected; waiting");
                    crate::transport::set_status("tx: host disc");
                    if let Err(e) = usb_api.wait_for_connection() {
                        log::warn!("webusb wait_for_connection: {e:?}");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                Err(e) => {
                    log::warn!("webusb write_buf: {e:?}");
                    crate::transport::set_status(format!("write err: {e:?}"));
                }
            }
        }
        total_handled += 1;
        crate::transport::set_status(format!("done #{total_handled}"));
    }
    Ok(())
}

fn reader_loop(
    mut ep_out: UsbEmulatedEndpoint,
    ep_out_num: u8,
    ep_in_num: u8,
    payload_tx: mpsc::Sender<Vec<u8>>,
) {
    let usb_api = UsbDeviceEmulation::default();
    let read_buf = match xous::map_memory(None, None, 0x1000, xous::MemoryFlags::W) {
        Ok(b) => b,
        Err(e) => {
            log::error!("webusb reader: map read buf: {e:?}");
            crate::transport::set_status(format!("reader: map err {e:?}"));
            return;
        }
    };
    crate::transport::set_status(format!("WebUSB reader started (out={ep_out_num} in={ep_in_num})"));
    let mut line = Vec::<u8>::new();
    let mut total_bytes_read: u64 = 0;
    let mut total_lines: u64 = 0;
    loop {
        let got = match ep_out.read_buf(read_buf, 64) {
            Ok(n) => n,
            Err(usb::error::UsbError::HostDisconnected) => {
                log::info!("webusb: host disconnected, waiting for reconnection");
                crate::transport::set_status("WebUSB: waiting for host");
                line.clear();
                if let Err(e) = usb_api.wait_for_connection() {
                    log::warn!("webusb wait_for_connection: {e:?}");
                }
                crate::transport::set_status(format!("WebUSB ready (EP out={ep_out_num}, in={ep_in_num})"));
                continue;
            }
            Err(e) => {
                log::warn!("webusb read_buf: {e:?}");
                crate::transport::set_status(format!("read err: {e:?}"));
                continue;
            }
        };
        if got == 0 {
            continue;
        }
        total_bytes_read += got as u64;
        crate::transport::set_status(format!("rx {got}B / {total_bytes_read} total / {total_lines} lines"));
        let chunk = &read_buf.as_slice::<u8>()[..got];
        for &b in chunk {
            if b == b'\n' {
                if line.is_empty() {
                    continue;
                }
                let payload = std::mem::take(&mut line);
                total_lines += 1;
                crate::transport::set_status(format!("got line {} ({}B)", total_lines, payload.len()));
                if payload_tx.send(payload).is_err() {
                    log::warn!("webusb dispatcher gone, reader exiting");
                    crate::transport::set_status("dispatcher gone");
                    return;
                }
            } else if b != b'\r' {
                if line.len() >= MAX_LINE_BYTES {
                    log::warn!("webusb: line exceeded {MAX_LINE_BYTES} bytes, dropping");
                    crate::transport::set_status("rx: oversize line dropped");
                    line.clear();
                    continue;
                }
                line.push(b);
            }
        }
    }
}

async fn dispatch(engine: &Engine<Keystore>, payload: &[u8]) -> Response {
    let req: Request = match serde_json::from_slice(payload) {
        Ok(r) => r,
        Err(e) => {
            let id = serde_json::from_slice::<serde_json::Value>(payload)
                .ok()
                .and_then(|v| v.get("id").and_then(|x| x.as_str()).map(|s| s.to_string()))
                .unwrap_or_else(|| "0".to_string());
            log::warn!("webusb parse error id={id}: {e}");
            // Don't echo serde_json::Error to the host — it leaks parser
            // framing (line/column, partial buffer) that helps a fuzzer.
            return Response::Err {
                id,
                error: ErrorPayload {
                    code: ErrorCode::InvalidRequest as i32,
                    message: "invalid request".to_string(),
                },
            };
        }
    };
    log::info!("webusb -> id={}", req.id);
    engine.handle(req, now_ms()).await
}

fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0) }

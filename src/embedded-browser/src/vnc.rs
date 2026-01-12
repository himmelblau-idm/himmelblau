/*
 * Himmelblau Embedded Browser Service - VNC Client
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use himmelblau_unix_common::unix_proto::{BrowserInputEvent, BrowserInputType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

// RFB Protocol constants
const RFB_VERSION_38: &[u8] = b"RFB 003.008\n";
const RFB_SECURITY_NONE: u8 = 1;

// Message types
const MSG_FRAMEBUFFER_UPDATE_REQUEST: u8 = 3;
const MSG_KEY_EVENT: u8 = 4;
const MSG_POINTER_EVENT: u8 = 5;
const MSG_FRAMEBUFFER_UPDATE: u8 = 0;

// Encoding types
const ENCODING_RAW: i32 = 0;

/// Connect to a VNC server and capture a frame
/// Note: We connect directly to the container IP on port 5900 (the internal VNC port)
pub async fn get_frame(container_ip: &str, _vnc_port: u16) -> Result<Vec<u8>, String> {
    // VNC inside the container always listens on port 5900
    let addr = format!("{}:5900", container_ip);

    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("Failed to connect to VNC server: {}", e))?;

    // Read server version
    let mut version_buf = [0u8; 12];
    stream
        .read_exact(&mut version_buf)
        .await
        .map_err(|e| format!("Failed to read VNC version: {}", e))?;

    debug!("VNC server version: {:?}", String::from_utf8_lossy(&version_buf));

    // Send client version
    stream
        .write_all(RFB_VERSION_38)
        .await
        .map_err(|e| format!("Failed to send VNC version: {}", e))?;

    // Read security types
    let num_security_types = stream
        .read_u8()
        .await
        .map_err(|e| format!("Failed to read security types count: {}", e))?;

    if num_security_types == 0 {
        // Read failure reason
        let reason_len = stream.read_u32().await.unwrap_or(0);
        let mut reason = vec![0u8; reason_len as usize];
        let _ = stream.read_exact(&mut reason).await;
        return Err(format!(
            "VNC connection failed: {}",
            String::from_utf8_lossy(&reason)
        ));
    }

    let mut security_types = vec![0u8; num_security_types as usize];
    stream
        .read_exact(&mut security_types)
        .await
        .map_err(|e| format!("Failed to read security types: {}", e))?;

    // Select "None" authentication
    if !security_types.contains(&RFB_SECURITY_NONE) {
        return Err("VNC server doesn't support 'None' authentication".to_string());
    }

    stream
        .write_u8(RFB_SECURITY_NONE)
        .await
        .map_err(|e| format!("Failed to select security type: {}", e))?;

    // Read security result
    let security_result = stream
        .read_u32()
        .await
        .map_err(|e| format!("Failed to read security result: {}", e))?;

    if security_result != 0 {
        return Err("VNC authentication failed".to_string());
    }

    // Send ClientInit (shared flag = 1)
    stream
        .write_u8(1)
        .await
        .map_err(|e| format!("Failed to send ClientInit: {}", e))?;

    // Read ServerInit
    let width = stream
        .read_u16()
        .await
        .map_err(|e| format!("Failed to read width: {}", e))?;
    let height = stream
        .read_u16()
        .await
        .map_err(|e| format!("Failed to read height: {}", e))?;

    debug!("VNC framebuffer size: {}x{}", width, height);

    // Read pixel format (16 bytes)
    let mut pixel_format = [0u8; 16];
    stream
        .read_exact(&mut pixel_format)
        .await
        .map_err(|e| format!("Failed to read pixel format: {}", e))?;

    // Read name length and name
    let name_len = stream
        .read_u32()
        .await
        .map_err(|e| format!("Failed to read name length: {}", e))?;
    let mut name = vec![0u8; name_len as usize];
    stream
        .read_exact(&mut name)
        .await
        .map_err(|e| format!("Failed to read desktop name: {}", e))?;

    debug!("VNC desktop name: {}", String::from_utf8_lossy(&name));

    // Request a framebuffer update
    let mut request = Vec::with_capacity(10);
    request.push(MSG_FRAMEBUFFER_UPDATE_REQUEST);
    request.push(0); // Not incremental - full update
    request.extend_from_slice(&0u16.to_be_bytes()); // x
    request.extend_from_slice(&0u16.to_be_bytes()); // y
    request.extend_from_slice(&width.to_be_bytes()); // width
    request.extend_from_slice(&height.to_be_bytes()); // height

    stream
        .write_all(&request)
        .await
        .map_err(|e| format!("Failed to send framebuffer request: {}", e))?;

    // Read framebuffer update
    let msg_type = stream
        .read_u8()
        .await
        .map_err(|e| format!("Failed to read message type: {}", e))?;

    if msg_type != MSG_FRAMEBUFFER_UPDATE {
        return Err(format!("Unexpected message type: {}", msg_type));
    }

    // Read padding
    stream
        .read_u8()
        .await
        .map_err(|e| format!("Failed to read padding: {}", e))?;

    // Read number of rectangles
    let num_rects = stream
        .read_u16()
        .await
        .map_err(|e| format!("Failed to read number of rectangles: {}", e))?;

    debug!("Receiving {} rectangles", num_rects);

    // For simplicity, we'll just collect raw pixel data
    // In a production implementation, you'd want to handle different encodings
    let mut frame_data = Vec::with_capacity((width as usize) * (height as usize) * 4);

    for _ in 0..num_rects {
        let rect_x = stream.read_u16().await.unwrap_or(0);
        let rect_y = stream.read_u16().await.unwrap_or(0);
        let rect_w = stream.read_u16().await.unwrap_or(0);
        let rect_h = stream.read_u16().await.unwrap_or(0);
        let encoding = stream.read_i32().await.unwrap_or(0);

        debug!(
            "Rectangle: {}x{} at ({}, {}), encoding: {}",
            rect_w, rect_h, rect_x, rect_y, encoding
        );

        if encoding == ENCODING_RAW {
            // Read raw pixel data (assuming 32-bit color depth)
            let pixel_count = (rect_w as usize) * (rect_h as usize) * 4;
            let mut pixels = vec![0u8; pixel_count];
            stream
                .read_exact(&mut pixels)
                .await
                .map_err(|e| format!("Failed to read pixel data: {}", e))?;
            frame_data.extend_from_slice(&pixels);
        } else {
            // Skip unsupported encodings
            warn!("Unsupported encoding: {}", encoding);
        }
    }

    Ok(frame_data)
}

/// Send an input event to the VNC server
/// Note: We connect directly to the container IP on port 5900 (the internal VNC port)
pub async fn send_input(
    container_ip: &str,
    _vnc_port: u16,
    event: &BrowserInputEvent,
) -> Result<(), String> {
    // VNC inside the container always listens on port 5900
    let addr = format!("{}:5900", container_ip);

    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("Failed to connect to VNC server: {}", e))?;

    // Perform handshake (simplified - reuse connection in production)
    perform_handshake(&mut stream).await?;

    match event.event_type {
        BrowserInputType::KeyDown | BrowserInputType::KeyUp => {
            let down_flag = match event.event_type {
                BrowserInputType::KeyDown => 1u8,
                BrowserInputType::KeyUp => 0u8,
                _ => 0u8,
            };

            let key_sym = event.key_sym.unwrap_or(0);

            let mut msg = Vec::with_capacity(8);
            msg.push(MSG_KEY_EVENT);
            msg.push(down_flag);
            msg.extend_from_slice(&[0u8; 2]); // padding
            msg.extend_from_slice(&key_sym.to_be_bytes());

            stream
                .write_all(&msg)
                .await
                .map_err(|e| format!("Failed to send key event: {}", e))?;
        }
        BrowserInputType::MouseMove
        | BrowserInputType::MouseDown
        | BrowserInputType::MouseUp
        | BrowserInputType::MouseScroll => {
            let x = event.x.unwrap_or(0) as u16;
            let y = event.y.unwrap_or(0) as u16;
            let button_mask = calculate_button_mask(event);

            let mut msg = Vec::with_capacity(6);
            msg.push(MSG_POINTER_EVENT);
            msg.push(button_mask);
            msg.extend_from_slice(&x.to_be_bytes());
            msg.extend_from_slice(&y.to_be_bytes());

            stream
                .write_all(&msg)
                .await
                .map_err(|e| format!("Failed to send pointer event: {}", e))?;
        }
    }

    Ok(())
}

/// Perform VNC handshake (simplified version for input sending)
async fn perform_handshake(stream: &mut TcpStream) -> Result<(), String> {
    // Read server version
    let mut version_buf = [0u8; 12];
    stream
        .read_exact(&mut version_buf)
        .await
        .map_err(|e| format!("Failed to read VNC version: {}", e))?;

    // Send client version
    stream
        .write_all(RFB_VERSION_38)
        .await
        .map_err(|e| format!("Failed to send VNC version: {}", e))?;

    // Read and handle security types
    let num_security_types = stream
        .read_u8()
        .await
        .map_err(|e| format!("Failed to read security types count: {}", e))?;

    if num_security_types == 0 {
        return Err("VNC connection rejected".to_string());
    }

    let mut security_types = vec![0u8; num_security_types as usize];
    stream
        .read_exact(&mut security_types)
        .await
        .map_err(|e| format!("Failed to read security types: {}", e))?;

    if !security_types.contains(&RFB_SECURITY_NONE) {
        return Err("VNC server doesn't support 'None' authentication".to_string());
    }

    stream
        .write_u8(RFB_SECURITY_NONE)
        .await
        .map_err(|e| format!("Failed to select security type: {}", e))?;

    // Read security result
    let security_result = stream
        .read_u32()
        .await
        .map_err(|e| format!("Failed to read security result: {}", e))?;

    if security_result != 0 {
        return Err("VNC authentication failed".to_string());
    }

    // Send ClientInit (shared flag = 1)
    stream
        .write_u8(1)
        .await
        .map_err(|e| format!("Failed to send ClientInit: {}", e))?;

    // Read ServerInit (we don't need the data, just need to consume it)
    let _width = stream.read_u16().await.unwrap_or(0);
    let _height = stream.read_u16().await.unwrap_or(0);

    // Read pixel format (16 bytes)
    let mut pixel_format = [0u8; 16];
    stream.read_exact(&mut pixel_format).await.ok();

    // Read name length and name
    let name_len = stream.read_u32().await.unwrap_or(0);
    let mut name = vec![0u8; name_len as usize];
    stream.read_exact(&mut name).await.ok();

    Ok(())
}

/// Calculate VNC button mask from input event
fn calculate_button_mask(event: &BrowserInputEvent) -> u8 {
    let mut mask = 0u8;

    match event.event_type {
        BrowserInputType::MouseDown => {
            if let Some(button) = event.button {
                match button {
                    1 => mask |= 0x01, // Left button
                    2 => mask |= 0x02, // Middle button
                    3 => mask |= 0x04, // Right button
                    _ => {}
                }
            }
        }
        BrowserInputType::MouseScroll => {
            // Mouse scroll is typically button 4 (up) or 5 (down)
            if let Some(button) = event.button {
                match button {
                    4 => mask |= 0x08, // Scroll up
                    5 => mask |= 0x10, // Scroll down
                    _ => {}
                }
            }
        }
        _ => {}
    }

    mask
}

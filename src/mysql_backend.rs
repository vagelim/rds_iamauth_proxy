//! MySQL wire protocol implementation for RDS IAM authentication.
//!
//! This module handles both sides of the MySQL protocol:
//! - **Backend (client-side):** Connects to RDS MySQL, negotiates SSL, and
//!   authenticates using the IAM token via `mysql_clear_password`.
//! - **Frontend (server-side):** Accepts connections from MySQL clients,
//!   performs the HandshakeV10 exchange, and extracts the username/database.

use bytes::{Buf, BufMut, BytesMut};
use eyre::{eyre, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tracing::{debug, info};

use crate::backend_config::{BackendConfig, DbSpec};

// ---------------------------------------------------------------------------
// MySQL capability flags
// ---------------------------------------------------------------------------

const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
const CLIENT_FOUND_ROWS: u32 = 0x0000_0002;
const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
const CLIENT_SSL: u32 = 0x0000_0800;
const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
const CLIENT_DEPRECATE_EOF: u32 = 0x0100_0000;

// Packet types
const OK_PACKET: u8 = 0x00;
const ERR_PACKET: u8 = 0xFF;
const EOF_PACKET: u8 = 0xFE;

// Character set: utf8mb4 general ci
const CHARSET_UTF8MB4: u8 = 45;

// Maximum packet size we advertise (16 MB)
const MAX_PACKET_SIZE: u32 = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Packet framing helpers
// ---------------------------------------------------------------------------

/// Read a single MySQL packet: [3-byte LE length][1-byte sequence][payload].
async fn read_packet<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let length = header[0] as usize | (header[1] as usize) << 8 | (header[2] as usize) << 16;
    if length > MAX_PACKET_SIZE as usize {
        return Err(eyre!(
            "MySQL packet length {} exceeds maximum {}",
            length,
            MAX_PACKET_SIZE
        ));
    }
    let seq_id = header[3];
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).await?;
    Ok((seq_id, payload))
}

/// Write a single MySQL packet.
async fn write_packet<S: AsyncWrite + Unpin>(
    stream: &mut S,
    seq_id: u8,
    payload: &[u8],
) -> Result<()> {
    let len = payload.len();
    if len > 0xFF_FFFF {
        return Err(eyre!("MySQL packet too large: {} bytes", len));
    }
    let mut header = [0u8; 4];
    header[0] = (len & 0xFF) as u8;
    header[1] = ((len >> 8) & 0xFF) as u8;
    header[2] = ((len >> 16) & 0xFF) as u8;
    header[3] = seq_id;
    stream.write_all(&header).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Parsed server HandshakeV10
// ---------------------------------------------------------------------------

#[derive(Debug)]
#[allow(dead_code)] // Fields parsed for protocol completeness; not all used yet.
struct HandshakeV10 {
    protocol_version: u8,
    server_version: String,
    connection_id: u32,
    auth_plugin_data_part1: Vec<u8>, // 8 bytes
    capability_flags: u32,
    character_set: u8,
    status_flags: u16,
    auth_plugin_data_part2: Vec<u8>, // up to 13 bytes
    auth_plugin_name: String,
}

impl HandshakeV10 {
    fn parse(data: &[u8]) -> Result<Self> {
        let mut buf = BytesMut::from(data);
        if buf.remaining() < 1 {
            return Err(eyre!("HandshakeV10: empty payload"));
        }
        let protocol_version = buf.get_u8();
        if protocol_version != 10 {
            return Err(eyre!(
                "Unsupported MySQL protocol version: {}",
                protocol_version
            ));
        }

        // Null-terminated server version string
        let nul_pos = buf
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| eyre!("HandshakeV10: missing server version NUL"))?;
        let server_version = String::from_utf8_lossy(&buf[..nul_pos]).to_string();
        buf.advance(nul_pos + 1);

        if buf.remaining() < 4 + 8 + 1 + 2 {
            return Err(eyre!("HandshakeV10: truncated after server version"));
        }
        let connection_id = buf.get_u32_le();
        let mut auth_plugin_data_part1 = vec![0u8; 8];
        buf.copy_to_slice(&mut auth_plugin_data_part1);
        let _filler = buf.get_u8(); // always 0x00

        let capability_flags_lower = buf.get_u16_le() as u32;

        // The rest is optional but RDS always sends it.
        if buf.remaining() < 1 + 2 + 2 {
            return Ok(HandshakeV10 {
                protocol_version,
                server_version,
                connection_id,
                auth_plugin_data_part1,
                capability_flags: capability_flags_lower,
                character_set: 0,
                status_flags: 0,
                auth_plugin_data_part2: vec![],
                auth_plugin_name: String::new(),
            });
        }

        let character_set = buf.get_u8();
        let status_flags = buf.get_u16_le();
        let capability_flags_upper = buf.get_u16_le() as u32;
        let capability_flags = capability_flags_lower | (capability_flags_upper << 16);

        // Length of auth-plugin-data (if CLIENT_PLUGIN_AUTH), else 0
        let auth_plugin_data_len = if capability_flags & CLIENT_PLUGIN_AUTH != 0 {
            buf.get_u8() as usize
        } else {
            let _ = buf.get_u8(); // 0x00
            0
        };

        // Reserved 10 bytes of zeros
        if buf.remaining() < 10 {
            return Err(eyre!("HandshakeV10: missing reserved bytes"));
        }
        buf.advance(10);

        // auth-plugin-data-part-2 (if CLIENT_SECURE_CONNECTION)
        let auth_plugin_data_part2 = if capability_flags & CLIENT_SECURE_CONNECTION != 0 {
            let part2_len = std::cmp::max(13, auth_plugin_data_len.saturating_sub(8));
            let actual_len = std::cmp::min(part2_len, buf.remaining());
            let mut part2 = vec![0u8; actual_len];
            buf.copy_to_slice(&mut part2);
            // Strip trailing NUL if present
            if part2.last() == Some(&0) {
                part2.pop();
            }
            part2
        } else {
            vec![]
        };

        // auth-plugin name (null-terminated)
        let auth_plugin_name = if capability_flags & CLIENT_PLUGIN_AUTH != 0 && buf.has_remaining() {
            let nul_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.remaining());
            let name = String::from_utf8_lossy(&buf[..nul_pos]).to_string();
            name
        } else {
            String::new()
        };

        Ok(HandshakeV10 {
            protocol_version,
            server_version,
            connection_id,
            auth_plugin_data_part1,
            capability_flags,
            character_set,
            status_flags,
            auth_plugin_data_part2,
            auth_plugin_name,
        })
    }
}

// ---------------------------------------------------------------------------
// Backend: connect to RDS MySQL with IAM token
// ---------------------------------------------------------------------------

/// Build the SSLRequest packet (32 bytes: capability_flags + max_packet_size +
/// character_set + 23 zero bytes).
fn build_ssl_request(server_caps: u32) -> Vec<u8> {
    // Note: we intentionally omit CLIENT_DEPRECATE_EOF so the backend uses
    // traditional EOF-based result set framing, matching what our proxy
    // advertises to the connecting client.
    let client_caps = (CLIENT_LONG_PASSWORD
        | CLIENT_FOUND_ROWS
        | CLIENT_LONG_FLAG
        | CLIENT_CONNECT_WITH_DB
        | CLIENT_PROTOCOL_41
        | CLIENT_SSL
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH
        | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)
        & (server_caps | CLIENT_SSL); // keep only what server supports, plus SSL

    let mut buf = Vec::with_capacity(32);
    buf.put_u32_le(client_caps);
    buf.put_u32_le(MAX_PACKET_SIZE);
    buf.put_u8(CHARSET_UTF8MB4);
    buf.extend_from_slice(&[0u8; 23]); // reserved
    buf
}

/// Build the HandshakeResponse41 packet.
fn build_handshake_response(
    server_caps: u32,
    username: &str,
    password: &str,
    database: &str,
) -> Vec<u8> {
    // Note: we intentionally omit CLIENT_DEPRECATE_EOF so the backend uses
    // traditional EOF-based result set framing, matching what our proxy
    // advertises to the connecting client.
    let mut client_caps = CLIENT_LONG_PASSWORD
        | CLIENT_FOUND_ROWS
        | CLIENT_LONG_FLAG
        | CLIENT_PROTOCOL_41
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH
        | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;

    // Always set CLIENT_CONNECT_WITH_DB — even with an empty database the
    // field must be present (as an empty NUL-terminated string) so the server
    // can correctly parse the auth_plugin_name that follows.
    client_caps |= CLIENT_CONNECT_WITH_DB;

    // Intersect with what server offered (except CLIENT_SSL which we already negotiated)
    client_caps &= server_caps | CLIENT_SSL;
    // Remove CLIENT_SSL from the response — we already upgraded
    client_caps &= !CLIENT_SSL;

    let auth_data = format!("{}\0", password); // IAM token + NUL terminator
    let auth_bytes = auth_data.as_bytes();

    let mut buf = Vec::with_capacity(128 + auth_bytes.len());
    buf.put_u32_le(client_caps);
    buf.put_u32_le(MAX_PACKET_SIZE);
    buf.put_u8(CHARSET_UTF8MB4);
    buf.extend_from_slice(&[0u8; 23]); // reserved

    // Username (null-terminated)
    buf.extend_from_slice(username.as_bytes());
    buf.push(0);

    // Auth response length-encoded
    let auth_len = auth_bytes.len();
    if auth_len < 251 {
        buf.push(auth_len as u8);
    } else if auth_len < 65536 {
        buf.push(0xFC);
        buf.put_u16_le(auth_len as u16);
    } else {
        buf.push(0xFD);
        buf.put_u8((auth_len & 0xFF) as u8);
        buf.put_u8(((auth_len >> 8) & 0xFF) as u8);
        buf.put_u8(((auth_len >> 16) & 0xFF) as u8);
    }
    buf.extend_from_slice(auth_bytes);

    // Database (null-terminated) — empty string if no database specified
    if !database.is_empty() {
        buf.extend_from_slice(database.as_bytes());
    }
    buf.push(0);

    // Auth plugin name (null-terminated)
    buf.extend_from_slice(b"mysql_clear_password\0");

    buf
}

/// Connect to a MySQL RDS backend, negotiate SSL, and authenticate using the
/// IAM auth token. Returns the authenticated TLS stream.
pub async fn mysql_connect(
    config: &BackendConfig,
    db_spec: &DbSpec,
    password: &str,
) -> Result<TlsStream<TcpStream>> {
    let mut stream = TcpStream::connect(config.connect_str()).await?;
    info!("Connected to MySQL backend at {}", config.connect_str());

    // Step 1: Read HandshakeV10 from the server
    let (seq_id, payload) = read_packet(&mut stream).await?;
    debug!("Received HandshakeV10 (seq={})", seq_id);

    // Check for ERR_Packet
    if !payload.is_empty() && payload[0] == ERR_PACKET {
        let err_msg = parse_err_packet(&payload)?;
        return Err(eyre!("MySQL server error during handshake: {}", err_msg));
    }

    let handshake = HandshakeV10::parse(&payload)?;
    info!(
        "MySQL server: {} (connection_id={}, auth_plugin={})",
        handshake.server_version, handshake.connection_id, handshake.auth_plugin_name
    );

    if handshake.capability_flags & CLIENT_SSL == 0 {
        return Err(eyre!(
            "MySQL server does not support SSL (required for IAM auth)"
        ));
    }

    // Step 2: Send SSLRequest (seq_id = 1)
    let ssl_request = build_ssl_request(handshake.capability_flags);
    write_packet(&mut stream, seq_id + 1, &ssl_request).await?;
    debug!("Sent SSLRequest");

    // Step 3: TLS upgrade
    let mut tls_stream = config.upgrade_to_tls_raw(stream).await?;
    debug!("TLS upgrade complete");

    // Step 4: Send HandshakeResponse41 (seq_id = 2) over TLS
    let response = build_handshake_response(
        handshake.capability_flags,
        db_spec.user(),
        password,
        db_spec.database(),
    );
    write_packet(&mut tls_stream, seq_id + 2, &response).await?;
    debug!("Sent HandshakeResponse41");

    // Step 5: Read auth result
    let (auth_result_seq, result_payload) = read_packet(&mut tls_stream).await?;
    if result_payload.is_empty() {
        return Err(eyre!("Empty response from MySQL after auth"));
    }

    match result_payload[0] {
        OK_PACKET => {
            info!("MySQL authentication successful");
        }
        ERR_PACKET => {
            let err_msg = parse_err_packet(&result_payload)?;
            return Err(eyre!("MySQL authentication failed: {}", err_msg));
        }
        EOF_PACKET => {
            // AuthSwitchRequest: [0xFE][plugin_name\0][plugin_data...]
            // The server wants us to use a different auth plugin. This is
            // common with RDS MySQL — the server's default plugin is
            // mysql_native_password but the iamdb user uses
            // AWSAuthenticationPlugin, so it sends an auth switch.
            let switch_payload = &result_payload[1..];
            let plugin_end = switch_payload
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(switch_payload.len());
            let requested_plugin =
                String::from_utf8_lossy(&switch_payload[..plugin_end]).to_string();
            info!(
                "MySQL auth switch requested to plugin: {}",
                requested_plugin
            );

            // For mysql_clear_password / AWSAuthenticationPlugin, send the
            // IAM token as cleartext + NUL terminator.
            if requested_plugin == "mysql_clear_password"
                || requested_plugin == "mysql_native_password"
            {
                // mysql_clear_password: send password + NUL
                let mut auth_data = Vec::with_capacity(password.len() + 1);
                auth_data.extend_from_slice(password.as_bytes());
                auth_data.push(0);
                let switch_seq = auth_result_seq + 1;
                write_packet(&mut tls_stream, switch_seq, &auth_data).await?;
                debug!("Sent auth switch response (seq={})", switch_seq);

                // Read final auth result
                let (_, final_payload) = read_packet(&mut tls_stream).await?;
                if final_payload.is_empty() {
                    return Err(eyre!("Empty response after auth switch"));
                }
                match final_payload[0] {
                    OK_PACKET => {
                        info!("MySQL authentication successful (after auth switch)");
                    }
                    ERR_PACKET => {
                        let err_msg = parse_err_packet(&final_payload)?;
                        return Err(eyre!(
                            "MySQL authentication failed after auth switch: {}",
                            err_msg
                        ));
                    }
                    other => {
                        return Err(eyre!(
                            "Unexpected response after auth switch: 0x{:02X}",
                            other
                        ));
                    }
                }
            } else {
                return Err(eyre!(
                    "MySQL server requested unsupported auth plugin: {}",
                    requested_plugin
                ));
            }
        }
        other => {
            return Err(eyre!("Unexpected MySQL response packet type: 0x{:02X}", other));
        }
    }

    Ok(tls_stream)
}

/// Parse an ERR_Packet to extract the error message.
fn parse_err_packet(payload: &[u8]) -> Result<String> {
    if payload.len() < 3 {
        return Ok("Unknown error (packet too short)".to_string());
    }
    // [0xFF][error_code: 2 bytes LE][#sql_state: 6 bytes][message]
    let error_code = payload[1] as u16 | (payload[2] as u16) << 8;
    let msg_start = if payload.len() > 3 && payload[3] == b'#' {
        // SQL state marker present: skip '#' + 5 bytes of state
        std::cmp::min(9, payload.len())
    } else {
        3
    };
    let message = String::from_utf8_lossy(&payload[msg_start..]).to_string();
    Ok(format!("Error {}: {}", error_code, message))
}

// ---------------------------------------------------------------------------
// Frontend: act as a MySQL server to accept client connections
// ---------------------------------------------------------------------------

/// Build a HandshakeV10 packet that the proxy sends to connecting MySQL clients.
/// We advertise `mysql_clear_password` as the auth plugin so clients send the
/// password (IAM token) in cleartext.
fn build_server_handshake(connection_id: u32) -> Vec<u8> {
    let server_version = b"5.7.0-rds-iam-proxy\0";
    let auth_plugin_name = b"mysql_clear_password\0";
    // Random-looking auth data (the client won't actually use it for
    // mysql_clear_password, but the protocol requires it)
    let auth_data_part1 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let auth_data_part2 = [
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x00,
    ]; // 12 bytes + NUL

    let capability_flags: u32 = CLIENT_LONG_PASSWORD
        | CLIENT_FOUND_ROWS
        | CLIENT_LONG_FLAG
        | CLIENT_CONNECT_WITH_DB
        | CLIENT_PROTOCOL_41
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH
        | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;

    let cap_lower = (capability_flags & 0xFFFF) as u16;
    let cap_upper = ((capability_flags >> 16) & 0xFFFF) as u16;

    let mut buf = Vec::with_capacity(128);
    buf.push(10); // protocol version
    buf.extend_from_slice(server_version);
    buf.put_u32_le(connection_id);
    buf.extend_from_slice(&auth_data_part1);
    buf.push(0x00); // filler
    buf.put_u16_le(cap_lower);
    buf.put_u8(CHARSET_UTF8MB4); // character set
    buf.put_u16_le(0x0002); // status flags: SERVER_STATUS_AUTOCOMMIT
    buf.put_u16_le(cap_upper);
    buf.put_u8(21); // auth plugin data length (8 + 13 = 21)
    buf.extend_from_slice(&[0u8; 10]); // reserved
    buf.extend_from_slice(&auth_data_part2);
    buf.extend_from_slice(auth_plugin_name);

    buf
}

/// Build an OK packet to send to the client after successful backend auth.
fn build_ok_packet() -> Vec<u8> {
    let mut buf = Vec::with_capacity(7);
    buf.push(OK_PACKET); // header
    buf.push(0); // affected_rows (lenenc 0)
    buf.push(0); // last_insert_id (lenenc 0)
    buf.put_u16_le(0x0002); // status flags: SERVER_STATUS_AUTOCOMMIT
    buf.put_u16_le(0); // warnings
    buf
}

/// Build an ERR packet to send to the client.
fn build_err_packet(error_code: u16, sql_state: &str, message: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9 + message.len());
    buf.push(ERR_PACKET);
    buf.put_u16_le(error_code);
    buf.push(b'#');
    buf.extend_from_slice(sql_state.as_bytes()); // 5 bytes
    buf.extend_from_slice(message.as_bytes());
    buf
}

/// Parse the client's HandshakeResponse41 to extract username and database.
fn parse_client_handshake(payload: &[u8]) -> Result<(String, String, u32)> {
    let mut buf = BytesMut::from(payload);
    if buf.remaining() < 32 {
        return Err(eyre!("Client handshake too short: {} bytes", buf.remaining()));
    }

    let client_flags = buf.get_u32_le();
    let _max_packet_size = buf.get_u32_le();
    let _charset = buf.get_u8();
    buf.advance(23); // reserved

    // Username (null-terminated)
    let username_end = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| eyre!("Missing NUL terminator in client username"))?;
    let username = String::from_utf8_lossy(&buf[..username_end]).to_string();
    buf.advance(username_end + 1);

    // Auth response — skip it (we don't need the client's password attempt;
    // we generate our own IAM token)
    if client_flags & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
        // Length-encoded auth data
        let auth_len = read_lenenc_int(&mut buf)?;
        let skip = std::cmp::min(auth_len as usize, buf.remaining());
        buf.advance(skip);
    } else if client_flags & CLIENT_SECURE_CONNECTION != 0 {
        // 1-byte length-prefixed auth data
        if buf.has_remaining() {
            let auth_len = buf.get_u8() as usize;
            let skip = std::cmp::min(auth_len, buf.remaining());
            buf.advance(skip);
        }
    } else {
        // Null-terminated auth data
        if let Some(pos) = buf.iter().position(|&b| b == 0) {
            buf.advance(pos + 1);
        }
    }

    // Database (null-terminated) if CLIENT_CONNECT_WITH_DB
    let database = if client_flags & CLIENT_CONNECT_WITH_DB != 0 && buf.has_remaining() {
        let db_end = buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(buf.remaining());
        let db = String::from_utf8_lossy(&buf[..db_end]).to_string();
        db
    } else {
        String::new()
    };

    Ok((username, database, client_flags))
}

/// Read a length-encoded integer from the buffer.
fn read_lenenc_int(buf: &mut BytesMut) -> Result<u64> {
    if !buf.has_remaining() {
        return Err(eyre!("Unexpected end of buffer reading lenenc int"));
    }
    let first = buf.get_u8();
    match first {
        0..=0xFA => Ok(first as u64),
        0xFC => {
            if buf.remaining() < 2 {
                return Err(eyre!("Truncated 2-byte lenenc int"));
            }
            Ok(buf.get_u16_le() as u64)
        }
        0xFD => {
            if buf.remaining() < 3 {
                return Err(eyre!("Truncated 3-byte lenenc int"));
            }
            let b0 = buf.get_u8() as u64;
            let b1 = buf.get_u8() as u64;
            let b2 = buf.get_u8() as u64;
            Ok(b0 | (b1 << 8) | (b2 << 16))
        }
        0xFE => {
            if buf.remaining() < 8 {
                return Err(eyre!("Truncated 8-byte lenenc int"));
            }
            Ok(buf.get_u64_le())
        }
        0xFB => Ok(0), // NULL in lenenc context
        0xFF => Err(eyre!("Invalid lenenc int prefix 0xFF (ERR marker)")),
    }
}

/// Handle a MySQL client connection. This is called from `main.rs` when
/// `db_type` is MySQL.
///
/// Flow:
/// 1. Send HandshakeV10 to client
/// 2. Receive client's HandshakeResponse41 (extract username/database)
/// 3. Connect to RDS MySQL backend with IAM auth
/// 4. Send OK to client
/// 5. Bidirectionally proxy all subsequent traffic
pub async fn mysql_handle_client(
    config: &BackendConfig,
    mut client: TcpStream,
    connection_id: u32,
) -> Result<()> {
    // Step 1: Send HandshakeV10 to client
    let handshake = build_server_handshake(connection_id);
    write_packet(&mut client, 0, &handshake).await?;
    debug!("Sent HandshakeV10 to client (connection_id={})", connection_id);

    // Step 2: Read client's response
    let (seq_id, client_payload) = read_packet(&mut client).await?;
    debug!("Received client handshake response (seq={})", seq_id);

    // Check if this is an SSLRequest (32 bytes, CLIENT_SSL set)
    // If so, we don't support client-side TLS (the client talks plaintext to
    // the local proxy; TLS is only on the proxy-to-RDS leg)
    if client_payload.len() == 32 {
        let client_flags =
            client_payload[0] as u32
            | (client_payload[1] as u32) << 8
            | (client_payload[2] as u32) << 16
            | (client_payload[3] as u32) << 24;
        if client_flags & CLIENT_SSL != 0 {
            // Client wants SSL to the proxy. This is unexpected for a local
            // proxy but we can handle it: just read the real handshake response
            // that follows (over plaintext — we don't actually TLS-upgrade the
            // client side).
            //
            // Actually, the MySQL client expects a TLS handshake after sending
            // SSLRequest. Since we're a local proxy, we'll reject SSL and send
            // an error.
            let err = build_err_packet(
                1045,
                "28000",
                "SSL not supported by proxy (connect without --ssl)",
            );
            write_packet(&mut client, seq_id + 1, &err).await?;
            return Err(eyre!("Client requested SSL to proxy; not supported"));
        }
    }

    let (username, database, _client_flags) = parse_client_handshake(&client_payload)?;
    info!(
        "MySQL client auth: user={}, database={}",
        username, database
    );

    if username.is_empty() {
        let err = build_err_packet(1045, "28000", "Username is required");
        write_packet(&mut client, seq_id + 1, &err).await?;
        return Err(eyre!("Client did not provide a username"));
    }

    // Step 3: Connect to RDS MySQL backend
    let db_spec = DbSpec::new(username, database);
    let server = match config.get_server_conn(db_spec).await {
        Ok(s) => s,
        Err(e) => {
            let err_msg = format!("Backend connection failed: {}", e);
            let err = build_err_packet(2003, "HY000", &err_msg);
            write_packet(&mut client, seq_id + 1, &err).await?;
            return Err(e);
        }
    };

    // Step 4: Send OK to client
    let ok = build_ok_packet();
    write_packet(&mut client, seq_id + 1, &ok).await?;
    info!("MySQL client authenticated, starting proxy");

    // Step 5: Bidirectional proxy
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = tokio::io::split(server);

    let client_to_server = async {
        tokio::io::copy(&mut client_read, &mut server_write).await?;
        server_write.shutdown().await
    };

    let server_to_client = async {
        tokio::io::copy(&mut server_read, &mut client_write).await?;
        client_write.shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

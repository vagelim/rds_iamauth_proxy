#[macro_use]
extern crate serde_derive;

use std::net::SocketAddr;

use byteorder::BigEndian;
use byteorder::ByteOrder;
use bytes::Bytes;
use clap::arg;
use clap::Command;
use config::Config;
use config::File;
use eyre::{eyre, Result};
use futures::SinkExt;
use memchr::memchr;
use tokio_rustls::client::TlsStream;
use tokio::io::split;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::signal;
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, Decoder};
use tracing::{debug, info};
use tracing_subscriber::filter::EnvFilter;

mod backend_config;
use backend_config::BackendConfig;
use backend_config::DbSpec;

fn setup() -> Result<()> {
    // Install the ring crypto provider for rustls before anything else uses it.
    // This is required because multiple crates (our TLS code, aws-sdk-signin)
    // depend on rustls but with different feature flags.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls ring crypto provider");

    if std::env::var("RUST_LIB_BACKTRACE").is_err() {
        std::env::set_var("RUST_LIB_BACKTRACE", "1")
    }
    color_eyre::install()?;

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    Ok(())
}

const SSL_REQUEST: i32 = 80877103;
const STARTUP_MESSAGE: i32 = 196608;
const SSL_NOT_ALLOWED: u8 = 0x4e;

struct Buffer {
    bytes: Bytes,
    idx: usize,
}

impl Buffer {
    #[inline]
    fn slice(&self) -> &[u8] {
        &self.bytes[self.idx..]
    }

    #[inline]
    fn read_cstr(&mut self) -> std::io::Result<Bytes> {
        match memchr(0, self.slice()) {
            Some(pos) => {
                let start = self.idx;
                let end = start + pos;
                let cstr = self.bytes.slice(start..end);
                self.idx = end + 1;
                Ok(cstr)
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            )),
        }
    }
}

fn parse_startup(src: Bytes) -> Result<DbSpec> {
    let mut user: Option<String> = None;
    let mut database: Option<String> = None;
    let mut buf = Buffer { bytes: src, idx: 0 };
    while user.is_none() || database.is_none() {
        let tag = buf.read_cstr()?;
        let value = buf.read_cstr()?;
        if tag == "user" {
            user = Some(std::str::from_utf8(&value[0..])?.to_owned());
        } else if tag == "database" {
            database = Some(std::str::from_utf8(&value[0..])?.to_owned());
        } else {
            debug!("ignoring tag {}", std::str::from_utf8(&tag[0..])?);
        }
    }
    let db = DbSpec::new(
        user.ok_or_else(|| eyre!("missing user"))?,
        database.ok_or_else(|| eyre!("missing database"))?,
    );
    Ok(db)
}

/// Send a PostgreSQL ErrorResponse to the client.
async fn send_pg_error(
    framed: &mut tokio_util::codec::Framed<&mut TcpStream, BytesCodec>,
    code: &str,
    message: &str,
) -> Result<()> {
    use bytes::BufMut;
    let mut buf = bytes::BytesMut::new();
    let severity = b"ERROR";
    let body_len = 1 + severity.len() + 1
        + 1 + code.len() + 1
        + 1 + message.len() + 1
        + 1;
    buf.put_u8(b'E');
    buf.put_i32((body_len + 4) as i32);
    buf.put_u8(b'S');
    buf.put_slice(severity);
    buf.put_u8(0);
    buf.put_u8(b'C');
    buf.put_slice(code.as_bytes());
    buf.put_u8(0);
    buf.put_u8(b'M');
    buf.put_slice(message.as_bytes());
    buf.put_u8(0);
    buf.put_u8(0);
    framed.send(buf.freeze()).await?;
    Ok(())
}

/// Ask the PostgreSQL client for a cleartext password and verify it against
/// the configured local_password.
async fn verify_pg_local_password(
    framed: &mut tokio_util::codec::Framed<&mut TcpStream, BytesCodec>,
    expected: &str,
) -> Result<()> {
    use bytes::BufMut;

    // Send AuthenticationCleartextPassword: 'R' + int32(8) + int32(3)
    let mut auth_req = bytes::BytesMut::with_capacity(9);
    auth_req.put_u8(b'R');
    auth_req.put_i32(8);
    auth_req.put_i32(3);
    framed.send(auth_req.freeze()).await?;

    // Read PasswordMessage: 'p' + int32(len) + string\0
    let resp = framed
        .try_next()
        .await?
        .ok_or_else(|| eyre!("Client closed before sending password"))?;

    if resp.is_empty() || resp[0] != b'p' {
        send_pg_error(framed, "28P01", "Expected password message").await?;
        return Err(eyre!("Expected PasswordMessage, got {:?}", resp.first()));
    }

    if resp.len() < 5 {
        send_pg_error(framed, "28P01", "Malformed password message").await?;
        return Err(eyre!("Password message too short"));
    }

    let password_bytes = &resp[5..];
    let password = if password_bytes.last() == Some(&0) {
        &password_bytes[..password_bytes.len() - 1]
    } else {
        password_bytes
    };

    let password_str = std::str::from_utf8(password)
        .map_err(|_| eyre!("Password is not valid UTF-8"))?;

    if password_str != expected {
        send_pg_error(framed, "28P01", "Invalid local proxy password").await?;
        return Err(eyre!("Local password mismatch"));
    }

    info!("Local password verified");
    Ok(())
}

async fn auth_backend(
    config: &BackendConfig,
    client: &mut TcpStream,
) -> Result<TlsStream<TcpStream>> {
    let mut framed = BytesCodec::new().framed(client);
    while let Some(message) = framed.next().await {
        match message {
            Ok(mut bytes) => {
                if bytes.len() < 8 {
                    return Err(eyre!("Received too-small packet"));
                } else {
                    let len = BigEndian::read_i32(&bytes[0..]);
                    let tag = BigEndian::read_i32(&bytes[4..]);
                    if len == 8 && tag == SSL_REQUEST {
                        framed.send(Bytes::from_static(&[SSL_NOT_ALLOWED])).await?;
                    } else if tag == STARTUP_MESSAGE {
                        if bytes.len() < (len as usize) {
                            return Err(eyre!(
                                "Packet wanted {} bytes, provided {}",
                                len,
                                bytes.len()
                            ));
                        }
                        let db = parse_startup(bytes.split_off(8).freeze())?;

                        // Verify local password if configured
                        if let Some(expected) = config.local_password() {
                            verify_pg_local_password(&mut framed, expected).await?;
                        }

                        let server = config.get_server_conn(db).await?;
                        return Ok(server);
                    } else {
                        return Err(eyre!("Unknown message tag {}", tag));
                    }
                }
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
    Err(eyre!("Client closed"))
}

async fn handle_client(
    config: &BackendConfig,
    mut client: TcpStream,
    _addr: SocketAddr,
) -> Result<()> {
    let server = auth_backend(config, &mut client).await?;

    let (mut ri, mut wi) = client.split();
    let (mut ro, mut wo) = split(server);
    let client_to_server = async {
        tokio::io::copy(&mut ri, &mut wo).await?;
        wo.shutdown().await
    };

    let server_to_client = async {
        tokio::io::copy(&mut ro, &mut wi).await?;
        wi.shutdown().await
    };
    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

async fn run_proxy(config: BackendConfig, listen_address: &str) -> Result<()> {
    let listener = TcpListener::bind(listen_address).await?;
    info!("Listening on {listen_address}");
    loop {
        let (stream, addr) = listener.accept().await?;

        info!("Got connection");
        let config_copy = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(&config_copy, stream, addr).await {
                info!("An error occurred in a client {:?}", e);
            } else {
                info!("done with client");
            }
        });
    }
}

fn load_config(config_file: &str) -> Result<BackendConfig> {
    let s = Config::builder()
        .add_source(File::with_name(config_file))
        .build()?;

    s.try_deserialize().map_err(|e| e.into())
}

#[tokio::main]
async fn main() -> Result<()> {
    setup()?;

    let matches = Command::new("rds_proxy")
        .version("1.0")
        .author("Greg Soltis <greg@goldfiglabs.com")
        .arg(arg!(-c --config <CONFIG> "Sets the proxy config file to use").default_value("proxy"))
        .arg(
            arg!(-l --listen <LISTEN> "Sets the address to listen on")
                .default_value("127.0.0.1:5435"),
        )
        .get_matches();

    let config_file = matches.get_one::<String>("config").unwrap();
    let listen_address = matches.get_one::<String>("listen").unwrap();

    let backend_config = load_config(config_file)?;

    // Run the proxy until we either get a Ctrl-C event or the proxy fails
    tokio::select! {
        _ = run_proxy(backend_config, listen_address) => {}
        _ = signal::ctrl_c() => {}
    }

    Ok(())
}

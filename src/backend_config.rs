use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use aws_config::BehaviorVersion;
use aws_credential_types::provider::ProvideCredentials;
use aws_sigv4::http_request::sign;
use aws_sigv4::http_request::SignableBody;
use aws_sigv4::http_request::SignableRequest;
use aws_sigv4::http_request::SigningSettings;
use aws_sigv4::sign::v4;
use bytes::{Bytes, BytesMut};
use eyre::{eyre, Result};
use fallible_iterator::FallibleIterator;
use futures::SinkExt;
use postgres_protocol::authentication::sasl;
use postgres_protocol::authentication::sasl::{ChannelBinding, ScramSha256};
use postgres_protocol::message::backend::Message;
use postgres_protocol::message::frontend;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use rustls::RootCertStore;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_stream::StreamExt;
use tracing::warn;
use tokio_util::codec::BytesCodec;
use tokio_util::codec::Framed;

/// The RDS global CA bundle, embedded at compile time.
/// Downloaded from https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
const RDS_GLOBAL_BUNDLE_PEM: &[u8] = include_bytes!("../certs/global-bundle.pem");

#[derive(Debug)]
pub struct DbSpec {
    user: String,
    database: String,
}

impl DbSpec {
    pub fn new(user: String, database: String) -> DbSpec {
        DbSpec { user, database }
    }

    fn startup_message(&self) -> Result<Bytes> {
        let mut params = vec![("client_encoding", "UTF8")];
        params.push(("user", self.user.as_str()));
        params.push(("database", self.database.as_str()));
        let mut buf = BytesMut::new();
        frontend::startup_message(params, &mut buf)?;
        Ok(buf.freeze())
    }
}

#[derive(Clone, Debug, Deserialize)]
struct Addr {
    hostname: String,
    port: u16,
}

impl Addr {
    fn connect_str(&self) -> String {
        format!("{}:{}", self.hostname, self.port)
    }
}

/// Build a rustls RootCertStore from a PEM bundle.
fn build_root_cert_store(pem_data: &[u8]) -> Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    let mut reader = BufReader::new(pem_data);
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|e| eyre!("Failed to parse PEM certificates: {}", e))?;

    if certs.is_empty() {
        return Err(eyre!("No certificates found in PEM bundle"));
    }

    for cert in certs {
        root_store
            .add(rustls::pki_types::CertificateDer::from(cert))
            .map_err(|e| eyre!("Failed to add certificate to root store: {}", e))?;
    }

    Ok(root_store)
}

#[derive(Clone, Debug, Deserialize)]
pub struct BackendConfig {
    endpoint: Addr,
    region: String,
    proxy_endpoint: Option<Addr>,
    /// Path to a custom CA bundle PEM file. When set, this is used instead of
    /// the embedded RDS global bundle to validate the server certificate.
    ca_bundle: Option<String>,
    /// Skip TLS certificate validation entirely. Only intended for use with
    /// SSH tunnels to localhost where the certificate hostname will not match.
    /// Defaults to false.
    #[serde(default)]
    danger_accept_invalid_certs: bool,
}

impl BackendConfig {
    fn connect_endpoint(&self) -> &Addr {
        match self.proxy_endpoint {
            Some(ref proxy) => proxy,
            None => &self.endpoint,
        }
    }

    pub async fn get_server_conn(
        &self,
        db_spec: DbSpec,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let password = get_rds_password(
            self.endpoint.hostname.as_ref(),
            self.endpoint.port,
            self.region.as_ref(),
            db_spec.user.as_str(),
        )
        .await?;
        let stream = self.backend_conn(db_spec, password).await?;
        Ok(stream)
    }

    async fn backend_conn(
        &self,
        db_spec: DbSpec,
        password: String,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let stream = TcpStream::connect(self.connect_endpoint().connect_str()).await?;
        let mut tls_stream = self.upgrade_to_tls(stream).await?;
        send_password(&db_spec, &mut tls_stream, password).await?;
        Ok(tls_stream)
    }

    async fn upgrade_to_tls(
        &self,
        mut tcp: TcpStream,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let mut buf = BytesMut::new();
        frontend::ssl_request(&mut buf);
        tcp.write_all(&buf).await?;
        let mut buf = [0];
        tcp.read_exact(&mut buf).await?;
        if buf[0] != b'S' {
            return Err(eyre!("server does not support TLS"));
        }

        let tls_config = if self.danger_accept_invalid_certs {
            warn!(
                "TLS certificate validation is disabled (danger_accept_invalid_certs=true). \
                 This should only be used with SSH tunnels to localhost."
            );
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerousVerifier))
                .with_no_client_auth()
        } else {
            let pem_data = match &self.ca_bundle {
                Some(path) => std::fs::read(path)
                    .map_err(|e| eyre!("Failed to read CA bundle from '{}': {}", path, e))?,
                None => RDS_GLOBAL_BUNDLE_PEM.to_vec(),
            };
            let root_store = build_root_cert_store(&pem_data)?;
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let server_name = ServerName::try_from(self.endpoint.hostname.clone())
            .map_err(|e| eyre!("Invalid server name '{}': {}", self.endpoint.hostname, e))?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let stream = connector.connect(server_name, tcp).await?;
        Ok(stream)
    }
}

/// A certificate verifier that accepts any certificate (for danger_accept_invalid_certs).
#[derive(Debug)]
struct DangerousVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

const HTTPS_LEN: usize = "https://".len();

pub async fn get_rds_password(
    rds_host: &str,
    port: u16,
    region_name: &str,
    username: &str,
) -> Result<String> {
    let config = aws_config::load_defaults(BehaviorVersion::v2024_03_28()).await;
    let provider = config
        .credentials_provider()
        .ok_or(eyre!("no credentials provider found"))?;
    let creds = provider.provide_credentials().await?;
    let identity = creds.into();

    let mut signing_settings = SigningSettings::default();
    signing_settings.expires_in = Some(Duration::from_secs(900));
    signing_settings.signature_location = aws_sigv4::http_request::SignatureLocation::QueryParams;

    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region_name)
        .name("rds-db")
        .time(SystemTime::now())
        .settings(signing_settings)
        .build()?;

    let mut url = url::Url::parse(&format!(
        "https://{rds_host}:{port}/?Action=connect&DBUser={username}"
    ))?;

    let signable_request = SignableRequest::new(
        "GET",
        url.as_str(),
        std::iter::empty(),
        SignableBody::Bytes(&[]),
    )?;
    let (instructions, _) = sign(signable_request, &signing_params.into())?.into_parts();

    for (name, value) in instructions.params() {
        url.query_pairs_mut().append_pair(name, value);
    }

    let password = url.to_string().split_off(HTTPS_LEN);
    Ok(password)
}

async fn send_password<S>(db_spec: &DbSpec, stream: &mut S, password: String) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let buf = db_spec.startup_message()?;
    let mut framed = Framed::new(stream, BytesCodec::new());
    framed.send(buf).await?;

    let mut resp = framed
        .try_next()
        .await?
        .ok_or_else(|| eyre!("backend closed connection before auth"))?;

    match Message::parse(&mut resp)? {
        Some(Message::AuthenticationCleartextPassword) => {
            let mut pw_buf = BytesMut::new();
            frontend::password_message(password.as_ref(), &mut pw_buf)?;
            framed.send(pw_buf.freeze()).await?;
            Ok(())
        }
        Some(Message::AuthenticationSasl(body)) => {
            // Check that SCRAM-SHA-256 is offered
            let mut has_scram = false;
            let mut mechanisms = body.mechanisms();
            while let Some(mechanism) = mechanisms.next()? {
                if mechanism == sasl::SCRAM_SHA_256 {
                    has_scram = true;
                }
            }
            if !has_scram {
                return Err(eyre!(
                    "Server offered SASL auth but SCRAM-SHA-256 is not available"
                ));
            }

            // Step 1: Send SASLInitialResponse with client-first-message
            let mut scram = ScramSha256::new(password.as_bytes(), ChannelBinding::unsupported());
            let mut sasl_buf = BytesMut::new();
            frontend::sasl_initial_response(sasl::SCRAM_SHA_256, scram.message(), &mut sasl_buf)?;
            framed.send(sasl_buf.freeze()).await?;

            // Step 2: Receive AuthenticationSASLContinue, send SASLResponse
            let mut resp = framed
                .try_next()
                .await?
                .ok_or_else(|| eyre!("backend closed connection during SASL"))?;
            match Message::parse(&mut resp)? {
                Some(Message::AuthenticationSaslContinue(body)) => {
                    scram
                        .update(body.data())
                        .map_err(|e| eyre!("SCRAM update failed: {}", e))?;
                }
                _ => return Err(eyre!("Expected AuthenticationSASLContinue")),
            }

            let mut sasl_buf = BytesMut::new();
            frontend::sasl_response(scram.message(), &mut sasl_buf)?;
            framed.send(sasl_buf.freeze()).await?;

            // Step 3: Receive AuthenticationSASLFinal or AuthenticationOk
            let mut resp = framed
                .try_next()
                .await?
                .ok_or_else(|| eyre!("backend closed connection during SASL final"))?;
            let raw_snapshot = resp.clone();
            match Message::parse(&mut resp)? {
                Some(Message::AuthenticationSaslFinal(body)) => {
                    scram
                        .finish(body.data())
                        .map_err(|e| eyre!("SCRAM verification failed: {}", e))?;
                }
                Some(Message::AuthenticationOk) => {
                    // Some servers skip SASLFinal and go straight to Ok
                }
                Some(Message::ErrorResponse(_)) => {
                    let raw_str = String::from_utf8_lossy(&raw_snapshot);
                    return Err(eyre!(
                        "Backend error after SASL response: {}",
                        raw_str
                    ));
                }
                _ => {
                    return Err(eyre!(
                        "Expected AuthenticationSASLFinal or AuthenticationOk (raw: {:?})",
                        &raw_snapshot[..std::cmp::min(raw_snapshot.len(), 128)]
                    ));
                }
            }

            Ok(())
        }
        Some(Message::ErrorResponse(_)) => Err(eyre!(
            "Backend returned error during auth (raw: {:?})",
            &resp[..std::cmp::min(resp.len(), 128)]
        )),
        _ => Err(eyre!("Unsupported authentication method")),
    }
}

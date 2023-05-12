use crate::transport::{
    service::TlsConnector,
    tls::{Certificate, Identity},
    Error,
};
use http::Uri;
use std::fmt;

/// Configures TLS settings for endpoints.
#[derive(Clone, Default)]
pub struct ClientTlsConfig {
    server_name: Option<tokio_rustls::rustls::ServerName>,
    cert: Option<Certificate>,
    identity: Option<Identity>,
}

impl fmt::Debug for ClientTlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientTlsConfig")
            .field("server_name", &self.server_name)
            .field("cert", &self.cert)
            .field("identity", &self.identity)
            .finish()
    }
}

impl ClientTlsConfig {
    /// Creates a new `ClientTlsConfig` using Rustls.
    pub fn new() -> Self {
        ClientTlsConfig {
            server_name: None,
            cert: None,
            identity: None,
        }
    }

    /// Directly sets the rustls server name to use for when setting up the initial connection.
    pub fn server_name(self, server_name: rustls::ServerName) -> Self {
        ClientTlsConfig {
            server_name: Some(server_name),
            ..self
        }
    }

    /// Sets the domain name against which to verify the server's TLS certificate.
    pub fn domain_name(self, domain_name: impl Into<String>) -> Self {
        let domain_name: String = domain_name.into();
        ClientTlsConfig {
            server_name: Some(domain_name.as_str().try_into().unwrap()),
            ..self
        }
    }

    /// Sets the CA Certificate against which to verify the server's TLS certificate.
    pub fn ca_certificate(self, ca_certificate: Certificate) -> Self {
        ClientTlsConfig {
            cert: Some(ca_certificate),
            ..self
        }
    }

    /// Sets the client identity to present to the server.
    pub fn identity(self, identity: Identity) -> Self {
        ClientTlsConfig {
            identity: Some(identity),
            ..self
        }
    }

    pub(crate) fn tls_connector(&self, uri: Uri) -> Result<TlsConnector, crate::Error> {
        let server_name = match &self.server_name {
            None => uri.host().ok_or_else(Error::new_invalid_uri)?.try_into()?,
            Some(server_name) => server_name.clone(),
        };
        TlsConnector::new(self.cert.clone(), self.identity.clone(), server_name)
    }
}

use std::fmt::Debug;
use std::sync::Arc;

use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{ClientConfig, SignatureAlgorithm, SignatureScheme};
use rustls_platform_verifier::BuilderVerifierExt;

use cdoc2::capsule::ecc::EllipticCurve;

use crate::Error;

pub trait EcdsaSigner: Debug + Send + Sync {
    fn curve(&self) -> EllipticCurve;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String>;
}

pub struct TlsIdentity(Arc<CertifiedKey>);

impl TlsIdentity {
    pub fn with_signer(certificate_chain: Vec<Vec<u8>>, signer: Arc<dyn EcdsaSigner>) -> Self {
        let chain = certificate_chain
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        TlsIdentity(Arc::new(CertifiedKey::new(
            chain,
            Arc::new(EcdsaKey(signer)),
        )))
    }
}

pub(crate) fn http_client(
    identity: Option<&TlsIdentity>,
) -> Result<reqwest::blocking::Client, Error> {
    let builder = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_platform_verifier()?;
    let config = match identity {
        Some(identity) => {
            builder.with_client_cert_resolver(Arc::new(ClientCertificate(identity.0.clone())))
        }
        None => builder.with_no_client_auth(),
    };
    let client = reqwest::blocking::Client::builder()
        .tls_backend_preconfigured(config)
        .build()?;
    Ok(client)
}

#[derive(Debug)]
struct ClientCertificate(Arc<CertifiedKey>);

impl ResolvesClientCert for ClientCertificate {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
struct EcdsaKey(Arc<dyn EcdsaSigner>);

impl SigningKey for EcdsaKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&self.scheme())
            .then(|| Box::new(self.clone()) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl Signer for EcdsaKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let signature = self.0.sign(message).map_err(rustls::Error::General)?;
        der_signature(self.0.curve(), &signature)
            .ok_or_else(|| rustls::Error::General("the signature has the wrong length".into()))
    }

    fn scheme(&self) -> SignatureScheme {
        match self.0.curve() {
            EllipticCurve::Secp256r1 => SignatureScheme::ECDSA_NISTP256_SHA256,
            EllipticCurve::Secp384r1 => SignatureScheme::ECDSA_NISTP384_SHA384,
            EllipticCurve::Secp521r1 => SignatureScheme::ECDSA_NISTP521_SHA512,
        }
    }
}

fn der_signature(curve: EllipticCurve, signature: &[u8]) -> Option<Vec<u8>> {
    let der = match curve {
        EllipticCurve::Secp256r1 => p256::ecdsa::Signature::from_slice(signature)
            .ok()?
            .to_der()
            .as_bytes()
            .to_vec(),
        EllipticCurve::Secp384r1 => p384::ecdsa::Signature::from_slice(signature)
            .ok()?
            .to_der()
            .as_bytes()
            .to_vec(),
        EllipticCurve::Secp521r1 => p521::ecdsa::Signature::from_slice(signature)
            .ok()?
            .to_der()
            .as_bytes()
            .to_vec(),
    };
    Some(der)
}

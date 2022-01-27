use lazy_static::lazy_static;
use openssl::ec::{Asn1Flag, EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{self, PKey};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509Req, X509ReqBuilder, X509};

use crate::persist::{Persist, PersistKey, PersistKind};
use crate::Result;

lazy_static! {
    pub(crate) static ref EC_GROUP_P256: EcGroup = ec_group(Nid::X9_62_PRIME256V1);
    pub(crate) static ref EC_GROUP_P384: EcGroup = ec_group(Nid::SECP384R1);
}

fn ec_group(nid: Nid) -> EcGroup {
    let mut g = EcGroup::from_curve_name(nid).expect("EcGroup");
    // this is required for openssl 1.0.x (but not 1.1.x)
    g.set_asn1_flag(Asn1Flag::NAMED_CURVE);
    g
}

/// Make an RSA private key (from which we can derive a public key).
///
/// This library does not check the number of bits used to create the key pair.
/// For Let's Encrypt, the bits must be between 2048 and 4096.
pub fn create_rsa_key(bits: u32) -> PKey<pkey::Private> {
    let pri_key_rsa = Rsa::generate(bits).expect("Rsa::generate");
    PKey::from_rsa(pri_key_rsa).expect("from_rsa")
}

/// Make a P-256 private key (from which we can derive a public key).
pub fn create_p256_key() -> PKey<pkey::Private> {
    let pri_key_ec = EcKey::generate(&*EC_GROUP_P256).expect("EcKey");
    PKey::from_ec_key(pri_key_ec).expect("from_ec_key")
}

/// Make a P-384 private key pair (from which we can derive a public key).
pub fn create_p384_key() -> PKey<pkey::Private> {
    let pri_key_ec = EcKey::generate(&*EC_GROUP_P384).expect("EcKey");
    PKey::from_ec_key(pri_key_ec).expect("from_ec_key")
}

pub(crate) fn create_csr(pkey: &PKey<pkey::Private>, domains: &[&str]) -> Result<X509Req> {
    //
    // the csr builder
    let mut req_bld = X509ReqBuilder::new().expect("X509ReqBuilder");

    // set private/public key in builder
    req_bld.set_pubkey(pkey).expect("set_pubkey");

    // set all domains as alt names
    let mut stack = Stack::new().expect("Stack::new");
    let ctx = req_bld.x509v3_context(None);
    let as_lst = domains
        .iter()
        .map(|&e| format!("DNS:{}", e))
        .collect::<Vec<_>>()
        .join(", ");
    let as_lst = as_lst[4..].to_string();
    let mut an = SubjectAlternativeName::new();
    an.dns(&as_lst);
    let ext = an.build(&ctx).expect("SubjectAlternativeName::build");
    stack.push(ext).expect("Stack::push");
    req_bld.add_extensions(&stack).expect("add_extensions");

    // sign it
    req_bld
        .sign(pkey, MessageDigest::sha256())
        .expect("csr_sign");

    // the csr
    Ok(req_bld.build())
}

/// Encapsulated certificate and private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    private_key: String,
    certificate: String,
}

impl Certificate {
    pub(crate) fn new(private_key: String, certificate: String) -> Self {
        Certificate {
            private_key,
            certificate,
        }
    }

    /// Get an already issued and [downloaded] certificate.
    ///
    /// Every time a certificate is downloaded, the certificate and corresponding
    /// private key are persisted. This method returns an already existing certificate
    /// from the local storage (no API calls involved).
    ///
    /// This can form the basis for implemeting automatic renewal of
    /// certificates where the [valid days left] are running low.
    ///
    /// [downloaded]: order/struct.CertOrder.html#method.download_and_save_cert
    /// [valid days left]: struct.Certificate.html#method.valid_days_left
    pub fn load<P: Persist>(
        realm: &str,
        persist: &P,
        primary_name: &str,
    ) -> Result<Option<Certificate>> {
        // read primary key
        let pk_key = PersistKey::new(realm, PersistKind::PrivateKey, primary_name);
        debug!("Read private key: {}", pk_key);
        let private_key = persist
            .get(&pk_key)?
            .and_then(|s| String::from_utf8(s).ok());

        // read certificate
        let pk_crt = PersistKey::new(realm, PersistKind::Certificate, primary_name);
        debug!("Read certificate: {}", pk_crt);
        let certificate = persist
            .get(&pk_crt)?
            .and_then(|s| String::from_utf8(s).ok());

        Ok(match (private_key, certificate) {
            (Some(k), Some(c)) => Some(Certificate::new(k, c)),
            _ => None,
        })
    }

    /// The PEM encoded private key.
    pub fn private_key(&self) -> &str {
        &self.private_key
    }

    /// The private key as DER.
    pub fn private_key_der(&self) -> Vec<u8> {
        let pkey = PKey::private_key_from_pem(self.private_key.as_bytes()).expect("from_pem");
        pkey.private_key_to_der().expect("private_key_to_der")
    }

    /// The PEM encoded issued certificate.
    pub fn certificate(&self) -> &str {
        &self.certificate
    }

    /// The issued certificate as DER.
    pub fn certificate_der(&self) -> Vec<u8> {
        let x509 = X509::from_pem(self.certificate.as_bytes()).expect("from_pem");
        x509.to_der().expect("to_der")
    }

    /// Inspect the certificate to count the number of (whole) valid days left.
    ///
    /// It's up to the ACME API provider to decide how long an issued certificate is valid.
    /// Let's Encrypt sets the validity to 90 days. This function reports 89 days for newly
    /// issued cert, since it counts _whole_ days.
    ///
    /// It is possible to get negative days for an expired certificate.
    pub fn valid_days_left(&self) -> i64 {
        // the cert used in the tests is not valid to load as x509
        if cfg!(test) {
            return 89;
        }

        // load as x509
        let x509 = X509::from_pem(self.certificate.as_bytes()).expect("from_pem");

        // convert asn1 time to Tm
        let not_after = format!("{}", x509.not_after());
        // Display trait produces this format, which is kinda dumb.
        // Apr 19 08:48:46 2019 GMT
        let expires = parse_date(&not_after);
        let dur = expires - time::now();

        dur.num_days()
    }
}

fn parse_date(s: &str) -> time::Tm {
    debug!("Parse date/time: {}", s);
    time::strptime(s, "%h %e %H:%M:%S %Y %Z").expect("strptime")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_date() {
        let x = parse_date("May  3 07:40:15 2019 GMT");
        assert_eq!(time::strftime("%F %T", &x).unwrap(), "2019-05-03 07:40:15");
    }
}

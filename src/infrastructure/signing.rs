use crate::{ObjectDefinition, ca::issuer::ObjectIssuer};
use anyhow::Result;
use rpki::crypto::{
    PublicKey,
    keys::PublicKeyFormat,
    signature::{Signature, SignatureAlgorithm},
    signer::{KeyError, Signer, SigningAlgorithm, SigningError},
};
use rpki::{
    repository::{
        cert::{Cert, TbsCert},
        crl::CrlEntry,
        manifest::FileAndHash,
        x509::{Time, Validity},
    },
    uri,
};
use rsa::{
    RsaPrivateKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs1v15::SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
    rand_core::{OsRng, RngCore},
    signature::{RandomizedSigner, SignatureEncoding},
    traits::PublicKeyParts,
};
use sha2::Sha256;
use std::{collections::HashMap, sync::RwLock};

pub(crate) type KeyId = String;

/// A key store with stable key identifiers.
///
/// The imported primary key remains persisted by the CA as `ca.key`; extra
/// keys created through the Signer interface live for this store instance.
/// This makes key identity explicit and allows a later PKCS#11/HSM backend to
/// implement the same interface.
pub(crate) trait SigningProvider: Send + Sync {
    fn public_key(&self) -> Result<PublicKey>;
    fn sign_ca_certificate(&self, cert: TbsCert) -> Result<Cert>;
    fn issue_object(
        &self,
        issuer: IssuerContext<'_>,
        request: ObjectSigningRequest<'_>,
    ) -> Result<SignedObjectOutput>;
    fn issue_crl(&self, issuer: IssuerContext<'_>, request: CrlSigningRequest) -> Result<Vec<u8>>;
    fn issue_manifest(
        &self,
        issuer: IssuerContext<'_>,
        request: ManifestSigningRequest<'_>,
    ) -> Result<Vec<u8>>;
}

pub(crate) struct IssuerContext<'a> {
    pub cert: &'a Cert,
    pub repository_uri: uri::Rsync,
    pub certificate_uri: uri::Rsync,
    pub crl_uri: uri::Rsync,
}

pub(crate) struct ObjectSigningRequest<'a> {
    pub definition: &'a ObjectDefinition,
    pub serial: u64,
    pub validity: Validity,
}

#[derive(Clone, Debug)]
pub(crate) struct SignedObjectOutput {
    pub name: String,
    pub bytes: Vec<u8>,
}

pub(crate) struct CrlSigningRequest {
    pub number: u64,
    pub this_update: Time,
    pub next_update: Time,
    pub revoked: Vec<CrlEntry>,
}

pub(crate) struct ManifestSigningRequest<'a> {
    pub serial: u64,
    pub manifest_number: u64,
    pub this_update: Time,
    pub next_update: Time,
    pub entries: &'a [FileAndHash<Vec<u8>, Vec<u8>>],
    pub manifest_uri: uri::Rsync,
}

pub(crate) struct SoftwareSigner {
    primary: KeyId,
    keys: RwLock<HashMap<KeyId, RsaPrivateKey>>,
}

/// A signing view with one pre-generated EE key. This makes the EE public
/// key available for RFC 6481 filename derivation before its SIA is built.
pub(crate) struct PreparedSoftwareSigner<'a> {
    parent: &'a SoftwareSigner,
    one_off: RsaPrivateKey,
    public: PublicKey,
}

impl SoftwareSigner {
    pub fn generate() -> Result<(Self, String), String> {
        let key = Self::new_key()?;
        let pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| e.to_string())?
            .to_string();
        Ok((Self::from_key(key)?, pem))
    }

    pub fn from_pem(pem: &str) -> Result<Self, String> {
        let key = RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|e| e.to_string())?;
        Self::from_key(key)
    }

    pub fn primary_key_id(&self) -> &KeyId {
        &self.primary
    }

    fn new_key() -> Result<RsaPrivateKey, String> {
        RsaPrivateKey::new(&mut OsRng, 2048).map_err(|e| e.to_string())
    }

    pub(crate) fn prepare_one_off(&self) -> Result<PreparedSoftwareSigner<'_>, String> {
        let one_off = Self::new_key()?;
        let public = Self::public_key(&one_off)?;
        Ok(PreparedSoftwareSigner {
            parent: self,
            one_off,
            public,
        })
    }

    fn from_key(key: RsaPrivateKey) -> Result<Self, String> {
        let public = Self::public_key(&key)?;
        let primary = public.key_identifier().to_string();
        let mut keys = HashMap::new();
        keys.insert(primary.clone(), key);
        Ok(Self {
            primary,
            keys: RwLock::new(keys),
        })
    }

    fn public_key(key: &RsaPrivateKey) -> Result<PublicKey, String> {
        let public = key.to_public_key();
        PublicKey::rsa_from_components(&public.n().to_bytes_be(), &public.e().to_bytes_be())
            .map_err(|e| e.to_string())
    }

    fn do_sign<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized>(
        key: &RsaPrivateKey,
        algorithm: Alg,
        data: &D,
    ) -> Result<Signature<Alg>, SigningError<String>> {
        if !matches!(algorithm.signing_algorithm(), SigningAlgorithm::RsaSha256) {
            return Err(SigningError::IncompatibleKey);
        }
        let key = SigningKey::<Sha256>::new(key.clone());
        let value = key.sign_with_rng(&mut OsRng, data.as_ref()).to_vec();
        Ok(Signature::new(algorithm, value.into()))
    }
}

impl PreparedSoftwareSigner<'_> {
    pub(crate) fn one_off_public_key(&self) -> &PublicKey {
        &self.public
    }

    pub(crate) fn primary_key_id(&self) -> &KeyId {
        self.parent.primary_key_id()
    }
}

impl Signer for PreparedSoftwareSigner<'_> {
    type KeyId = KeyId;
    type Error = String;

    fn create_key(&self, format: PublicKeyFormat) -> Result<KeyId, String> {
        self.parent.create_key(format)
    }

    fn get_key_info(&self, id: &KeyId) -> Result<PublicKey, KeyError<String>> {
        self.parent.get_key_info(id)
    }

    fn destroy_key(&self, id: &KeyId) -> Result<(), KeyError<String>> {
        self.parent.destroy_key(id)
    }

    fn sign<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized>(
        &self,
        id: &KeyId,
        algorithm: Alg,
        data: &D,
    ) -> Result<Signature<Alg>, SigningError<String>> {
        self.parent.sign(id, algorithm, data)
    }

    fn sign_one_off<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: Alg,
        data: &D,
    ) -> Result<(Signature<Alg>, PublicKey), String> {
        let signature = SoftwareSigner::do_sign(&self.one_off, algorithm, data)
            .map_err(|error| error.to_string())?;
        Ok((signature, self.public.clone()))
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), String> {
        self.parent.rand(target)
    }
}

impl Signer for SoftwareSigner {
    type KeyId = KeyId;
    type Error = String;

    fn create_key(&self, format: PublicKeyFormat) -> Result<KeyId, String> {
        if format != PublicKeyFormat::Rsa {
            return Err("only RSA keys are supported for RPKI CA operations".to_owned());
        }
        let key = Self::new_key()?;
        let id = Self::public_key(&key)?.key_identifier().to_string();
        self.keys
            .write()
            .map_err(|_| "key store lock poisoned".to_owned())?
            .insert(id.clone(), key);
        Ok(id)
    }

    fn get_key_info(&self, id: &KeyId) -> Result<PublicKey, KeyError<String>> {
        let keys = self
            .keys
            .read()
            .map_err(|_| KeyError::Signer("key store lock poisoned".to_owned()))?;
        let key = keys.get(id).ok_or(KeyError::KeyNotFound)?;
        Self::public_key(key).map_err(KeyError::Signer)
    }

    fn destroy_key(&self, id: &KeyId) -> Result<(), KeyError<String>> {
        if id == &self.primary {
            return Err(KeyError::Signer(
                "the active CA key cannot be destroyed".to_owned(),
            ));
        }
        self.keys
            .write()
            .map_err(|_| KeyError::Signer("key store lock poisoned".to_owned()))?
            .remove(id)
            .map(|_| ())
            .ok_or(KeyError::KeyNotFound)
    }

    fn sign<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized>(
        &self,
        id: &KeyId,
        algorithm: Alg,
        data: &D,
    ) -> Result<Signature<Alg>, SigningError<String>> {
        let keys = self
            .keys
            .read()
            .map_err(|_| SigningError::Signer("key store lock poisoned".to_owned()))?;
        let key = keys.get(id).ok_or(SigningError::KeyNotFound)?;
        Self::do_sign(key, algorithm, data)
    }

    fn sign_one_off<Alg: SignatureAlgorithm, D: AsRef<[u8]> + ?Sized>(
        &self,
        algorithm: Alg,
        data: &D,
    ) -> Result<(Signature<Alg>, PublicKey), String> {
        let key = Self::new_key()?;
        let public = Self::public_key(&key)?;
        let signature = Self::do_sign(&key, algorithm, data).map_err(|e| e.to_string())?;
        Ok((signature, public))
    }

    fn rand(&self, target: &mut [u8]) -> Result<(), String> {
        OsRng.try_fill_bytes(target).map_err(|e| e.to_string())
    }
}

impl SigningProvider for SoftwareSigner {
    fn public_key(&self) -> Result<PublicKey> {
        self.get_key_info(self.primary_key_id())
            .map_err(|err| anyhow::anyhow!("cannot read CA public key: {err}"))
    }

    fn sign_ca_certificate(&self, cert: TbsCert) -> Result<Cert> {
        cert.into_cert(self, self.primary_key_id())
            .map_err(|err| anyhow::anyhow!("CA certificate signing failed: {err}"))
    }

    fn issue_object(
        &self,
        issuer: IssuerContext<'_>,
        request: ObjectSigningRequest<'_>,
    ) -> Result<SignedObjectOutput> {
        let issuer = ObjectIssuer::new(
            issuer.cert,
            self,
            issuer.repository_uri,
            issuer.certificate_uri,
            issuer.crl_uri,
        );
        match request.definition {
            ObjectDefinition::Roa(definition) => {
                issuer.issue_roa(definition, request.serial, request.validity)
            }
            ObjectDefinition::Aspa(definition) => {
                issuer.issue_aspa(definition, request.serial, request.validity)
            }
        }
    }

    fn issue_crl(&self, issuer: IssuerContext<'_>, request: CrlSigningRequest) -> Result<Vec<u8>> {
        ObjectIssuer::new(
            issuer.cert,
            self,
            issuer.repository_uri,
            issuer.certificate_uri,
            issuer.crl_uri,
        )
        .issue_crl(
            request.number,
            request.this_update,
            request.next_update,
            request.revoked,
        )
    }

    fn issue_manifest(
        &self,
        issuer: IssuerContext<'_>,
        request: ManifestSigningRequest<'_>,
    ) -> Result<Vec<u8>> {
        ObjectIssuer::new(
            issuer.cert,
            self,
            issuer.repository_uri,
            issuer.certificate_uri,
            issuer.crl_uri,
        )
        .issue_manifest(
            request.serial,
            request.manifest_number,
            request.this_update,
            request.next_update,
            request.entries,
            request.manifest_uri,
        )
    }
}

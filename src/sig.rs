use ring::signature::{ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_FIXED, UnparsedPublicKey};
use rustls_pki_types::{
    AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
    alg_id::{ECDSA_P384, ECDSA_SHA384},
};

#[derive(Debug)]
pub struct EcdsaFixed;

impl SignatureVerificationAlgorithm for EcdsaFixed {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, public_key)
            .verify(message, signature)
            .map_err(|_| InvalidSignature)?;

        Ok(())
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        ECDSA_P384
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        ECDSA_SHA384
    }
}

#[derive(Debug)]
pub struct EcdsaAsn1;

impl SignatureVerificationAlgorithm for EcdsaAsn1 {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, public_key)
            .verify(message, signature)
            .map_err(|_| InvalidSignature)?;

        Ok(())
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        ECDSA_P384
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        ECDSA_SHA384
    }
}

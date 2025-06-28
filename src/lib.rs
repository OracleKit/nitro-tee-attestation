use crate::sig::{EcdsaAsn1, EcdsaFixed};
use crate::types::Attestation;
use coset::{CborSerializable, CoseSign1, cbor::from_reader};
use coset::{CoseError, TaggedCborSerializable};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, UnixTime};
use std::time::Duration;
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};

mod sig;
mod types;

const ROOT_CERT_PEM: &[u8] = include_bytes!("./root.pem");

pub fn parse_and_verify(attestation_doc: &[u8], epoch_secs: u64) -> Result<Attestation, String> {
    let sign1 = decode_cose_sign1(attestation_doc)?;

    let attestation: Attestation =
        from_reader(sign1.payload.as_ref().unwrap().as_slice()).map_err(|e| e.to_string())?;
    validate_parsed_attestation(&attestation)?;

    let mut certs: Vec<CertificateDer> = attestation
        .cabundle
        .iter()
        .map(|cert| CertificateDer::from_slice(cert.as_slice()))
        .collect();

    certs.reverse(); // optimizes the chain path search

    let end_cert = CertificateDer::from_slice(&attestation.certificate.as_slice());
    let end_cert = EndEntityCert::try_from(&end_cert).map_err(|e| e.to_string())?;

    let root_cert = CertificateDer::from_pem_slice(ROOT_CERT_PEM).map_err(|e| e.to_string())?;
    let root_cert = anchor_from_trusted_cert(&root_cert).map_err(|e| e.to_string())?;

    end_cert
        .verify_for_usage(
            &[&EcdsaAsn1],
            &[root_cert],
            &certs,
            UnixTime::since_unix_epoch(Duration::from_secs(epoch_secs)),
            KeyUsage::client_auth(),
            None,
            None,
        )
        .map_err(|e| e.to_string())?;

    end_cert
        .verify_signature(&EcdsaFixed, &sign1.tbs_data(&[]), &sign1.signature)
        .map_err(|e| e.to_string())?;

    Ok(attestation)
}

fn decode_cose_sign1(buf: &[u8]) -> Result<CoseSign1, String> {
    CoseSign1::from_slice(buf)
        .or_else(|e| {
            if let CoseError::UnexpectedItem(got, _) = e {
                if got == "tag" {
                    return CoseSign1::from_tagged_slice(buf);
                }
            }

            Err(e)
        })
        .map_err(|e| e.to_string())
}

fn validate_parsed_attestation(_: &Attestation) -> Result<(), String> {
    Ok(())
}

use nitro_tee_attestation::parse_and_verify;

const TEST_ATTESTATION_RAW: &[u8] = include_bytes!("./attestation.hex");

#[test]
fn test_verify_success() {
    let attestation = hex::decode(TEST_ATTESTATION_RAW).unwrap();
    let result = parse_and_verify(&attestation, 1750957383);

    assert_eq!(result.is_ok(), true);
}

use super::*;

#[test]
fn token_header_roundtrip_and_clock_bounds() {
    let now = 1_700_000_000;
    let header = encode_header(true, now);
    let mut token = header.to_vec();
    token.extend_from_slice(b"payload");

    let meta = token_meta(Some(&token)).unwrap();
    assert!(meta.is_ready(now));
    assert!(meta.is_ready(now + MAX_AGE_SECS));
    assert!(!meta.is_ready(now + MAX_AGE_SECS + 1));
    assert!(!meta.is_ready(now - 1));

    assert!(matches!(
        validate_token(&token, true, now - 1),
        Err(UnlockError::Expired(_))
    ));
    assert!(matches!(
        validate_token(&token, true, now + MAX_AGE_SECS + 1),
        Err(UnlockError::Expired(_))
    ));
}

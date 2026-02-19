use ed25519_dalek::SigningKey;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use syftbox_crypto_protocol::SyftPrivateKeys;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[test]
fn test_private_keys_getters_expose_expected_material() {
    let mut rng = StdRng::from_seed([42u8; 32]);

    let mut identity_seed = [0u8; 32];
    rng.fill_bytes(&mut identity_seed);
    let identity = SigningKey::from_bytes(&identity_seed);

    let mut identity_dh_seed = [0u8; 32];
    rng.fill_bytes(&mut identity_dh_seed);
    let identity_dh = StaticSecret::from(identity_dh_seed);

    let mut signed_prekey_seed = [0u8; 32];
    rng.fill_bytes(&mut signed_prekey_seed);
    let signed_prekey = StaticSecret::from(signed_prekey_seed);

    let identity_pub_bytes = *identity.verifying_key().as_bytes();
    let identity_dh_pub_bytes = *X25519PublicKey::from(&identity_dh).as_bytes();
    let signed_prekey_pub_bytes = *X25519PublicKey::from(&signed_prekey).as_bytes();

    let keys = SyftPrivateKeys::new(identity, identity_dh, signed_prekey);

    assert_eq!(
        keys.identity().verifying_key().as_bytes(),
        &identity_pub_bytes
    );
    assert_eq!(
        X25519PublicKey::from(keys.identity_dh()).as_bytes(),
        &identity_dh_pub_bytes
    );
    assert_eq!(
        X25519PublicKey::from(keys.signed_pre_key()).as_bytes(),
        &signed_prekey_pub_bytes
    );
}

#[test]
fn test_to_public_bundle_signatures_valid() {
    let mut rng = StdRng::from_seed([7u8; 32]);

    let mut identity_seed = [0u8; 32];
    rng.fill_bytes(&mut identity_seed);
    let identity = SigningKey::from_bytes(&identity_seed);

    let mut identity_dh_seed = [0u8; 32];
    rng.fill_bytes(&mut identity_dh_seed);
    let identity_dh = StaticSecret::from(identity_dh_seed);

    let mut signed_prekey_seed = [0u8; 32];
    rng.fill_bytes(&mut signed_prekey_seed);
    let signed_prekey = StaticSecret::from(signed_prekey_seed);

    let keys = SyftPrivateKeys::new(identity, identity_dh, signed_prekey);

    let bundle = keys
        .to_public_bundle(&mut rng)
        .expect("bundle creation succeeds");

    assert!(bundle.verify_signatures());
}

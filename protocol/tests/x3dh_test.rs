use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use x25519_dalek::{PublicKey, StaticSecret};

fn static_secret_from_rng(rng: &mut ChaCha20Rng) -> StaticSecret {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    StaticSecret::from(bytes)
}

/// Test X3DH key component generation
///
/// This demonstrates the basic cryptographic building blocks of X3DH:
/// - Identity DH key pairs (IK_A, IK_B) - long-term authentication keys
/// - Signed prekeys (SPK_B) - medium-term keys signed by identity signing key
/// - Ephemeral keys (EK_A) - per-message forward secrecy
#[test]
fn test_x3dh_key_generation() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);

    let alice_identity_dh = static_secret_from_rng(&mut rng);
    let bob_identity_dh = static_secret_from_rng(&mut rng);

    let alice_identity_dh_pub = PublicKey::from(&alice_identity_dh);
    let bob_identity_dh_pub = PublicKey::from(&bob_identity_dh);

    assert_eq!(alice_identity_dh_pub.as_bytes().len(), 32);
    assert_eq!(bob_identity_dh_pub.as_bytes().len(), 32);

    let bob_signed_prekey = static_secret_from_rng(&mut rng);
    let bob_signed_prekey_pub = PublicKey::from(&bob_signed_prekey);
    assert_eq!(bob_signed_prekey_pub.as_bytes().len(), 32);

    let _alice_ephemeral = static_secret_from_rng(&mut rng);
}

/// Test standard X3DH key agreement protocol
///
/// This implements the core DH operations:
/// - DH1 = DH(IK_A, SPK_B)
/// - DH2 = DH(EK_A, IK_B)
/// - DH3 = DH(EK_A, SPK_B)
/// - SK = KDF(DH1 || DH2 || DH3)
#[test]
fn test_x3dh_key_agreement() {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);

    let alice_identity_dh = static_secret_from_rng(&mut rng);
    let alice_ephemeral = static_secret_from_rng(&mut rng);

    let bob_identity_dh = static_secret_from_rng(&mut rng);
    let bob_signed_prekey = static_secret_from_rng(&mut rng);

    let bob_identity_dh_pub = PublicKey::from(&bob_identity_dh);
    let bob_signed_prekey_pub = PublicKey::from(&bob_signed_prekey);

    let alice_identity_dh_pub = PublicKey::from(&alice_identity_dh);
    let alice_ephemeral_pub = PublicKey::from(&alice_ephemeral);

    // Alice side
    let dh1_alice = alice_identity_dh
        .diffie_hellman(&bob_signed_prekey_pub)
        .to_bytes();
    let dh2_alice = alice_ephemeral
        .diffie_hellman(&bob_identity_dh_pub)
        .to_bytes();
    let dh3_alice = alice_ephemeral
        .diffie_hellman(&bob_signed_prekey_pub)
        .to_bytes();

    // Bob side
    let dh1_bob = bob_signed_prekey
        .diffie_hellman(&alice_identity_dh_pub)
        .to_bytes();
    let dh2_bob = bob_identity_dh
        .diffie_hellman(&alice_ephemeral_pub)
        .to_bytes();
    let dh3_bob = bob_signed_prekey
        .diffie_hellman(&alice_ephemeral_pub)
        .to_bytes();

    assert_eq!(dh1_alice, dh1_bob);
    assert_eq!(dh2_alice, dh2_bob);
    assert_eq!(dh3_alice, dh3_bob);

    let mut key_material_alice = Vec::new();
    key_material_alice.extend_from_slice(&dh1_alice);
    key_material_alice.extend_from_slice(&dh2_alice);
    key_material_alice.extend_from_slice(&dh3_alice);

    let mut key_material_bob = Vec::new();
    key_material_bob.extend_from_slice(&dh1_bob);
    key_material_bob.extend_from_slice(&dh2_bob);
    key_material_bob.extend_from_slice(&dh3_bob);

    assert_eq!(key_material_alice, key_material_bob);

    use hkdf::Hkdf;
    use sha2::Sha256;

    let salt = [0xFFu8; 32];
    let info = b"X3DH-SyftBox";

    let hk = Hkdf::<Sha256>::new(Some(&salt), &key_material_alice);
    let mut shared_secret_alice = [0u8; 32];
    hk.expand(info, &mut shared_secret_alice)
        .expect("hkdf expand");

    let hk = Hkdf::<Sha256>::new(Some(&salt), &key_material_bob);
    let mut shared_secret_bob = [0u8; 32];
    hk.expand(info, &mut shared_secret_bob)
        .expect("hkdf expand");

    assert_eq!(shared_secret_alice, shared_secret_bob);
}

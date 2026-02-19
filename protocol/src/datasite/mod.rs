pub mod bytes;
pub mod context;
pub mod crypto;

pub use bytes::{
    BytesReadOpts, BytesReadOutput, BytesWriteOpts, BytesWriteOutcome, read_bytes, write_bytes,
};
pub use context::{
    AppContext, DatasiteConfig, DatasiteConfigRaw, atomic_write, bundle_path_for_identity,
    detect_single_identity, ensure_vault_layout, expand_home, fallback_identity_from_path,
    home_dir, read_datasite_config, read_identity_from_key, resolve_data_path, resolve_identity,
    resolve_roots, resolve_shadow_path, resolve_vault, sanitize_identity, yes_no,
};
pub use crypto::{
    PublicBundleInfo, decrypt_envelope_for_recipient, encrypt_envelope_for_recipient,
    load_cached_bundle, load_private_keys_for_identity, load_private_keys_from_file,
    parse_optional_envelope, parse_public_bundle, resolve_recipient_bundle,
    resolve_sender_bundle_for_decrypt, serialize_private_keys_to_file,
};

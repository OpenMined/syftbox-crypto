//! Constant-time utilities to prevent timing side-channel attacks.

use subtle::{Choice, ConstantTimeEq};

/// Compares an optional identity string with a target identity in constant time.
///
/// This prevents timing attacks where an attacker could infer the correct identity
/// by measuring comparison time. The function always iterates through the maximum
/// length of both strings, regardless of where a mismatch occurs.
///
/// # Returns
/// - `Choice(1)` if candidate matches target exactly (same bytes, same length)
/// - `Choice(0)` if candidate is None, different bytes, or different length
pub(super) fn ct_identity_match(candidate: Option<&str>, target: &str) -> Choice {
    match candidate {
        Some(identity) => {
            let lhs = identity.as_bytes();
            let rhs = target.as_bytes();
            let max_len = lhs.len().max(rhs.len());
            let mut diff = 0u8;
            for i in 0..max_len {
                let l = *lhs.get(i).unwrap_or(&0);
                let r = *rhs.get(i).unwrap_or(&0);
                diff |= l ^ r;
            }
            let len_match = (lhs.len() as u64).ct_eq(&(rhs.len() as u64));
            let bytes_match = diff.ct_eq(&0);
            len_match & bytes_match
        }
        None => Choice::from(0),
    }
}

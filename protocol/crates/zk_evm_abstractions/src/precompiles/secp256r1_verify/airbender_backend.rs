use super::Secp256r1Backend;

// ==============================================================================
// Delegated Backend
// ==============================================================================
pub(super) struct DelegatedSecp256r1Backend;

impl Secp256r1Backend for DelegatedSecp256r1Backend {
    fn verify(
        digest: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
        x: &[u8; 32],
        y: &[u8; 32],
    ) -> Result<bool, ()> {
        super::parse_public_key(x, y)?;

        match airbender_crypto::secp256r1::verify(digest, r, s, x, y) {
            Ok(is_valid) => Ok(is_valid),
            // A recovered point at infinity is an invalid ECDSA signature, not
            // malformed precompile input. Legacy completes verification and
            // returns `false`, which writes the successful-but-invalid output
            // word pair `[1, 0]`.
            Err(airbender_crypto::secp256r1::Secp256r1Err::RecoveredInfinity) => Ok(false),
            Err(_) => Err(()),
        }
    }
}

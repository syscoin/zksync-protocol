use zkevm_opcode_defs::k256;
use zkevm_opcode_defs::k256::ecdsa::VerifyingKey;

use super::ECRecoverBackend;

// ==============================================================================
// Legacy Backend
// ==============================================================================
pub(super) struct LegacyECRecoverBackend;

impl ECRecoverBackend for LegacyECRecoverBackend {
    fn recover(
        digest: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
        rec_id: u8,
    ) -> Result<VerifyingKey, ()> {
        use k256::ecdsa::{RecoveryId, Signature};

        let signature = Signature::from_scalars(*r, *s).map_err(|_| ())?;
        let recovery_id = RecoveryId::try_from(rec_id).unwrap();

        // ECRECOVER accepts high-S signatures with their original recovery parity.
        VerifyingKey::recover_from_prehash(digest, &signature, recovery_id).map_err(|_| ())
    }
}

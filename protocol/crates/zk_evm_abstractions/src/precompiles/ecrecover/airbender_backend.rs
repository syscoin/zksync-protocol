use zkevm_opcode_defs::k256::ecdsa::VerifyingKey;

use super::ECRecoverBackend;

// ==============================================================================
// Delegated Backend
// ==============================================================================
pub(super) struct DelegatedECRecoverBackend;

impl ECRecoverBackend for DelegatedECRecoverBackend {
    fn recover(
        digest: &[u8; 32],
        r: &[u8; 32],
        s: &[u8; 32],
        rec_id: u8,
    ) -> Result<VerifyingKey, ()> {
        use airbender_crypto::k256::ecdsa::{RecoveryId, Signature};
        use airbender_crypto::k256::elliptic_curve::ops::Reduce;
        use airbender_crypto::k256::{FieldBytes, Scalar};
        use airbender_crypto::secp256k1;

        let signature = Signature::from_scalars(*r, *s).map_err(|_| ())?;
        let recovery_id = RecoveryId::try_from(rec_id).unwrap();

        let message = <Scalar as Reduce<FieldBytes>>::reduce(digest.into());

        // Delegated recovery checks the point and constructs the key for this
        // signature. A second verification repeats the scalar multiplications
        // on the non-delegated backend.
        let recovered_key =
            secp256k1::recover(&message, &signature, &recovery_id).map_err(|_| ())?;
        let encoded = recovered_key.to_encoded_point(false);
        VerifyingKey::from_sec1_bytes(encoded.as_bytes()).map_err(|_| ())
    }
}

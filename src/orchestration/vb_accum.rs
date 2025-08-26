use anyhow::Result;
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ethers::prelude::*;

use crate::orchestration::crypto::encoding::{eip2537_g1_to_affine, eip2537_g2_to_affine};
use vb_accumulator::positive::{Accumulator as VbAccTrait};
use vb_accumulator::setup::{PublicKey as AccPublicKey, SetupParams as AccSetup};
use vb_accumulator::witness::MembershipWitness as VbMembershipWitness;

/// Convenience wrapper around vb_accumulator params and public key
pub struct VbEnv {
    pub params: AccSetup<Bls12_381>,
    pub pk: AccPublicKey<Bls12_381>,
}

impl VbEnv {
    pub async fn from_onchain<M: Middleware + 'static>(
        params_contract: &Contract<M>,
        cred_name: &str,
    ) -> Result<Self> {
        let (g1_b, _h0_b, g2_b): (ethers::types::Bytes, ethers::types::Bytes, ethers::types::Bytes) =
            params_contract.method("getG1H0G2ByName", (cred_name.to_string(),))?.call().await?;
        let pk_acc_bytes: ethers::types::Bytes = params_contract
            .method("getOpenerPkG2ByName", (cred_name.to_string(),))?
            .call()
            .await
            .unwrap_or_else(|_| ethers::types::Bytes::from_static(&[]));
        if pk_acc_bytes.0.len() != 256 {
            anyhow::bail!("opener pkG2 missing in Params");
        }
        let params = AccSetup::<Bls12_381> {
            P: eip2537_g1_to_affine(&g1_b.0[..])?,
            P_tilde: eip2537_g2_to_affine(&g2_b.0[..])?,
        };
        let pk = AccPublicKey::<Bls12_381>(eip2537_g2_to_affine(&pk_acc_bytes.0[..])?);
        Ok(Self { params, pk })
    }

    /// Verify that e is a member of accumulator with value v_new, using witness w_old = v_old
    pub fn verify_add_result(
        &self,
        v_old: <Bls12_381 as Pairing>::G1Affine,
        v_new: <Bls12_381 as Pairing>::G1Affine,
        e_fr: ark_bls12_381::Fr,
    ) -> bool {
        vb_accumulator::positive::PositiveAccumulator::<<Bls12_381 as Pairing>::G1Affine>::verify_membership_given_accumulated::<Bls12_381>(
            &v_new,
            &e_fr,
            &VbMembershipWitness::<<Bls12_381 as Pairing>::G1Affine>(v_old),
            &self.pk,
            &self.params,
        )
    }
}

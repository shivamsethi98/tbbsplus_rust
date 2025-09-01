//! Typed wrappers for on-chain EIP-2537 encodings and Fr/U256 bridging.
use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ethers::types::U256;
use serde::{Deserialize, Serializer, Deserializer};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EipG1(pub [u8; 128]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EipG2(pub [u8; 256]);

impl TryFrom<Vec<u8>> for EipG1 {
    type Error = anyhow::Error;
    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        if v.len() != 128 { anyhow::bail!("EipG1 expects 128 bytes, got {}", v.len()); }
        let mut arr = [0u8; 128];
        arr.copy_from_slice(&v);
        Ok(EipG1(arr))
    }
}

impl TryFrom<Vec<u8>> for EipG2 {
    type Error = anyhow::Error;
    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        if v.len() != 256 { anyhow::bail!("EipG2 expects 256 bytes, got {}", v.len()); }
        let mut arr = [0u8; 256];
        arr.copy_from_slice(&v);
        Ok(EipG2(arr))
    }
}

impl EipG1 {
    pub fn to_affine(&self) -> anyhow::Result<<Bls12_381 as Pairing>::G1Affine> {
    crate::orchestration::crypto::encoding::eip2537_g1_to_affine(&self.0)
    }
    pub fn from_affine(p: &<Bls12_381 as Pairing>::G1Affine) -> Self {
    let b = crate::orchestration::crypto::encoding::g1_to_eip2537_bytes(p);
        let mut arr = [0u8; 128];
        arr.copy_from_slice(&b);
        EipG1(arr)
    }
}

impl EipG2 {
    pub fn to_affine(&self) -> anyhow::Result<<Bls12_381 as Pairing>::G2Affine> {
    crate::orchestration::crypto::encoding::eip2537_g2_to_affine(&self.0)
    }
    pub fn from_affine(p: &<Bls12_381 as Pairing>::G2Affine) -> Self {
    let b = crate::orchestration::crypto::encoding::g2_to_eip2537_bytes(p);
        let mut arr = [0u8; 256];
        arr.copy_from_slice(&b);
        EipG2(arr)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FrU256(#[serde(with = "hex_u256")] pub U256);

impl From<Fr> for FrU256 { fn from(f: Fr) -> Self { FrU256(crate::orchestration::crypto::encoding::fr_to_u256(&f)) } }
impl TryFrom<FrU256> for Fr {
    type Error = anyhow::Error;
    fn try_from(v: FrU256) -> Result<Self, Self::Error> { Ok(crate::orchestration::crypto::encoding::u256_to_fr::<Fr>(&v.0)) }
}

// serde helper for 0x-prefixed big-endian 32B U256
pub mod hex_u256 {
    use super::*;
    pub fn serialize<S: Serializer>(u: &U256, s: S) -> Result<S::Ok, S::Error> {
        let mut be = [0u8; 32];
        u.to_big_endian(&mut be);
        let hexs = format!("0x{}", hex::encode(be));
        s.serialize_str(&hexs)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U256, D::Error> {
        let s = String::deserialize(d)?;
        let b = hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)?;
        let mut be = [0u8; 32];
        if b.len() > 32 { return Err(serde::de::Error::custom("too long")); }
        be[(32 - b.len())..].copy_from_slice(&b);
        Ok(U256::from_big_endian(&be))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use ark_std::UniformRand;

    #[test]
    fn test_hex_u256_roundtrip() {
        let vals = [
            U256::zero(),
            U256::from(1u64),
            U256::from_big_endian(&[0xFFu8; 32]),
            U256::from_dec_str("1234567890123456789012345678901234567890").unwrap(),
        ];
        for v in vals {
            let s = FrU256(v);
            let j = serde_json::to_string(&s).unwrap();
            let back: FrU256 = serde_json::from_str(&j).unwrap();
            assert_eq!(s.0, back.0);
        }
    }

    #[test]
    fn test_eip_g1_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let p = <Bls12_381 as Pairing>::G1Affine::rand(&mut rng);
        let w = EipG1::from_affine(&p);
        let back = w.to_affine().unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn test_eip_g2_roundtrip() {
        let mut rng = StdRng::seed_from_u64(99);
        let p = <Bls12_381 as Pairing>::G2Affine::rand(&mut rng);
        let w = EipG2::from_affine(&p);
        let back = w.to_affine().unwrap();
        assert_eq!(p, back);
    }
}

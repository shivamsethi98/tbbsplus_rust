use ark_bls12_381::Fr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Msg {
    // TTP -> Issuer: assign id and key share
    Assign { id: u16, sk_share: String },
    // Issuer -> User: signature share
    SigShare { id: u16, share: String },
    // User -> Issuer: signing request with messages
    SignReq { messages: Vec<String> },
    // Control: hello/ready
    Hello,
    Ready,
}

pub fn fr_to_hex(x: &Fr) -> String {
    use ark_serialize::CanonicalSerialize;
    let mut bytes = Vec::new();
    x.serialize_compressed(&mut bytes).unwrap();
    hex::encode(bytes)
}

pub fn fr_from_hex(s: &str) -> anyhow::Result<Fr> {
    use ark_serialize::CanonicalDeserialize;
    let bytes = hex::decode(s)?;
    Ok(Fr::deserialize_compressed(&*bytes)?)
}

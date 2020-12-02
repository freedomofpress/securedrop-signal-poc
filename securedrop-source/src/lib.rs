use wasm_bindgen::prelude::*;
extern crate console_error_panic_hook;
use std::panic;

use hex::{decode, encode};
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use libsignal_protocol_rust::IdentityKeyStore;
use libsignal_protocol_rust::{
    IdentityKeyPair, InMemSignalProtocolStore, KeyPair, ProtocolAddress,
};

const DEVICE_ID: u32 = 1;

#[derive(Serialize, Deserialize)]
pub struct RegistrationBundle {
    pub signed_prekey_id: u32,
    pub signed_prekey: String,
    pub signed_prekey_timestamp: u64,
    pub identity_key: String,
    pub prekey_signature: String,
    pub registration_id: u32,
}

// For putting logic when the wasm module is first loaded
#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    Ok(())
}

#[wasm_bindgen]
pub fn generate(source_uuid: String) -> Result<JsValue, JsValue> {
    // Let panic messages pass through to the JavaScript console for debugging
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    let mut csprng = OsRng;

    let source_address = ProtocolAddress::new(source_uuid, DEVICE_ID);
    let registration_id: u32 = csprng.gen();

    let identity_key = IdentityKeyPair::generate(&mut csprng);

    // This struct will hold our session, identity, prekey and sender key stores.
    // TODO: We'll be saving this (encrypted) on the server as we communicate.
    let mut store = match InMemSignalProtocolStore::new(identity_key, registration_id) {
        Ok(data) => data,
        Err(err) => return Err(err.to_string().into()),
    };
    // TODO: make a SecureDropSourceSession struct in securedrop-source that can be serialized?

    let signed_pre_key_pair = KeyPair::generate(&mut csprng);

    // Not using ? here since the trait
    // `std::convert::From<libsignal_protocol_rust::error::SignalProtocolError>`
    // is not implemented for `wasm_bindgen::JsValue`.
    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
    let keypair = match store.get_identity_key_pair(None) {
        Ok(data) => data,
        Err(err) => return Err(err.to_string().into()),
    };
    let prekey_signature = match keypair
        .private_key()
        .calculate_signature(&signed_pre_key_public, &mut csprng)
    {
        Ok(data) => data,
        Err(err) => return Err(err.to_string().into()),
    };
    // TODO: Add one-time prekeys later

    // The below does not work on Wasm, workaround TODO (compiles but produces runtime panic):
    // https://github.com/rust-lang/rust/issues/48564#issuecomment-505114709
    // let start = SystemTime::now();
    // let signed_prekey_timestamp = start
    //    .duration_since(UNIX_EPOCH)
    //    .expect("Time went backwards");
    let signed_prekey_timestamp = 1234123;
    // TODO: Ensure server side rejects duplicated signed_pre_key_ids
    let signed_prekey_id: u32 = csprng.gen();

    let registration_data = RegistrationBundle {
        signed_prekey_id,
        signed_prekey: hex::encode(signed_pre_key_public),
        //signed_prekey_timestamp: signed_prekey_timestamp.as_secs(),
        signed_prekey_timestamp,
        identity_key: hex::encode(identity_key.public_key().serialize()),
        prekey_signature: hex::encode(prekey_signature),
        registration_id,
    };

    match JsValue::from_serde(&registration_data) {
        Ok(data) => Ok(data),
        Err(err) => Err(err.to_string().into()),
    }
}

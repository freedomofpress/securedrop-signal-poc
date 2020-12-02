use wasm_bindgen::prelude::*;

use rand::Rng;
use rand::rngs::OsRng;
use uuid::Uuid;
use std::time::{SystemTime, UNIX_EPOCH};

use libsignal_protocol_rust::{ProtocolAddress, IdentityKeyPair, InMemSignalProtocolStore, KeyPair};
use libsignal_protocol_rust::IdentityKeyStore;

const DEVICE_ID: u32 = 1;

/// Calling external functions in Javascript from Rust
#[wasm_bindgen]
extern {
    pub fn alert(s: &str);
}

/// Producing Rust functions that Javascript can call
#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello, {}!", name));
}

// Called when the wasm module is instantiated
#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    // Use `web_sys`'s global `window` function to get a handle on the global
    // window object.
    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");
    let body = document.body().expect("document should have a body");

    // Manufacture the element we're gonna append
    let val = document.create_element("p")?;
    val.set_inner_html("Hello from Rust!");

    body.append_child(&val)?;

    Ok(())
}

#[wasm_bindgen]
pub fn generate(source_uuid: String) -> Result<bool, JsValue> {
    let mut csprng = OsRng;

    // Generating required key material for source Signal registration
    let source_address = ProtocolAddress::new(source_uuid, DEVICE_ID);
    //let source_registration_id = Uuid::new_v4();
    let source_registration_id = csprng.gen();

    // Long-term signal identity key
    let identity_key = IdentityKeyPair::generate(&mut csprng);

    // This struct will hold our session, identity, prekey and sender key stores.
    // TODO: We'll be saving this (encrypted) on the server as we communicate.
    let mut store = match InMemSignalProtocolStore::new(identity_key, source_registration_id) {
        Ok(data) => data,
        Err(err) => return Err(err.to_string().into()),
    };
    //TODO: make a SecureDropSourceSession struct in securedrop-source that can be serialized?

    // Signed prekey
    let signed_pre_key_pair = KeyPair::generate(&mut csprng);

    // Not using ? here since the trait
    // `std::convert::From<libsignal_protocol_rust::error::SignalProtocolError>`
    // is not implemented for `wasm_bindgen::JsValue`.
    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
    let keypair = match store.get_identity_key_pair(None) {
        Ok(data) => data,
        Err(err) => return Err(err.to_string().into()),
    };
    let signed_pre_key_signature = match keypair.private_key().calculate_signature(&signed_pre_key_public, &mut csprng) {
        Ok(data) => data,
        Err(err) => return Err(err.to_string().into()),
    };

    // TODO: one-time prekey

    let start = SystemTime::now();
    let signed_prekey_timestamp = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    // TODO: Ensure server side rejects duplicated signed_pre_key_ids
    let signed_pre_key_id: u32 = csprng.gen();

    // TODO: POST to server here
    // signed_pre_key_id
    // signed_prekey
    // signed_prekey_timestamp
    // identity_key
    // signed_pre_key_signature
    // registration_id

    Ok(true)
}

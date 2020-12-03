use wasm_bindgen::prelude::*;
extern crate console_error_panic_hook;
use std::panic;

use hex::{decode, encode};
use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use libsignal_protocol_rust::{IdentityKeyStore, SignedPreKeyStore};
use libsignal_protocol_rust::{
    IdentityKeyPair, InMemSignalProtocolStore, KeyPair, ProtocolAddress,
    SignedPreKeyRecord, PreKeyBundle, PublicKey, IdentityKey, process_prekey_bundle,
    message_encrypt, message_decrypt
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

#[wasm_bindgen]
pub struct SecureDropSourceSession {
    store: InMemSignalProtocolStore,
    pub registration_id: u32,
}

#[wasm_bindgen]
impl SecureDropSourceSession {
    pub fn new(source_uuid: String) -> Result<SecureDropSourceSession, JsValue> {
        panic::set_hook(Box::new(console_error_panic_hook::hook));

        let mut csprng = OsRng;

        let source_address = ProtocolAddress::new(source_uuid, DEVICE_ID);
        let registration_id: u32 = csprng.gen();

        let identity_key = IdentityKeyPair::generate(&mut csprng);

        // This struct will hold our session, identity, prekey and sender key stores.
        // TODO: We'll be saving this (encrypted) on the server as we communicate.
        match InMemSignalProtocolStore::new(identity_key, registration_id) {
            Ok(store) => Ok(SecureDropSourceSession{ store, registration_id }),
            Err(err) => Err(err.to_string().into()),
        }
    }

    /// Called when we first generate keys prior to initial registration.
    pub fn generate(&mut self) -> Result<JsValue, JsValue> {
        // Lets panic messages pass through to the JavaScript console for debugging
        panic::set_hook(Box::new(console_error_panic_hook::hook));

        let mut csprng = OsRng;

        let signed_pre_key_pair = KeyPair::generate(&mut csprng);

        // Not using ? here since the trait
        // `std::convert::From<libsignal_protocol_rust::error::SignalProtocolError>`
        // is not implemented for `wasm_bindgen::JsValue`.
        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let keypair = match self.store.get_identity_key_pair(None) {
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

        let signed_prekey_record = SignedPreKeyRecord::new(
            signed_prekey_id,
            signed_prekey_timestamp,
            &signed_pre_key_pair,
            &prekey_signature
        );
        self.store.save_signed_pre_key(signed_prekey_id, &signed_prekey_record, None);

        let registration_data = RegistrationBundle {
            signed_prekey_id,
            signed_prekey: hex::encode(signed_pre_key_public),
            //signed_prekey_timestamp: signed_prekey_timestamp.as_secs(),
            signed_prekey_timestamp,
            identity_key: hex::encode(keypair.public_key().serialize()),
            prekey_signature: hex::encode(prekey_signature),
            registration_id: self.registration_id,
        };

        match JsValue::from_serde(&registration_data) {
            Ok(data) => Ok(data),
            Err(err) => Err(err.to_string().into()),
        }
    }

    /// TODO: Prevent duplicate registration IDs from source and journalist
    /// (matters on journalist side)
    pub fn process_prekey_bundle(&mut self,
        registration_id: u32,
        identity_key: String,
        address: String,
        signed_prekey_id: u32,
        signed_prekey: String,
        signed_prekey_sig: String,
    ) -> Result<bool, JsValue> {
        panic::set_hook(Box::new(console_error_panic_hook::hook));

        let mut csprng = OsRng;
        let journo_address = ProtocolAddress::new(address, DEVICE_ID);
        let signed_prekey_bytes = match hex::decode(signed_prekey) {
            Ok(data) => data,
            Err(err) => return Err(err.to_string().into()),
        };
        let signed_prekey_sig = match hex::decode(signed_prekey_sig) {
            Ok(data) => data,
            Err(err) => return Err(err.to_string().into()),
        };
        let identity_key_bytes = match hex::decode(identity_key) {
            Ok(data) => data,
            Err(err) => return Err(err.to_string().into()),
        };
        let identity_key = match IdentityKey::decode(&identity_key_bytes) {
            Ok(data) => data,
            Err(err) => return Err(err.to_string().into()),
        };
        let signed_prekey = match PublicKey::deserialize(&signed_prekey_bytes) {
            Ok(data) => data,
            Err(err) => return Err(err.to_string().into()),
        };
        let pre_key_bundle = match PreKeyBundle::new(
            registration_id,
            DEVICE_ID,
            None, // pre key id TK
            None, // pre key TK
            signed_prekey_id,
            signed_prekey,
            signed_prekey_sig,
            identity_key,
        ) {
            Ok(data) => data,
            Err(err) => return Err(err.to_string().into()),
        };
        match process_prekey_bundle(
            &journo_address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &pre_key_bundle,
            &mut csprng,
            None,
        ) {
            Ok(data) => Ok(true),
            Err(err) => Err(err.to_string().into()),
        }
    }

    pub fn encrypt(&mut self,
        address: String,
        ptext: String) -> Result<String, JsValue> {
        panic::set_hook(Box::new(console_error_panic_hook::hook));

        let recipient = ProtocolAddress::new(address, DEVICE_ID);
        match message_encrypt(
            &ptext.into_bytes(),
            &recipient,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            None
        ) {
            Ok(data) => Ok(hex::encode(data.serialize())),
            Err(err) => Err(err.to_string().into()),
        }
    }
}

// For putting logic when the wasm module is first loaded
#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    Ok(())
}



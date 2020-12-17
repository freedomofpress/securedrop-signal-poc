use wasm_bindgen::prelude::*;
extern crate console_error_panic_hook;
use std::panic;

use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
// use std::time::{SystemTime, UNIX_EPOCH};

use libsignal_protocol_rust::{
    message_decrypt, message_encrypt, process_prekey_bundle, CiphertextMessage, IdentityKey,
    IdentityKeyPair, InMemSignalProtocolStore, KeyPair, PreKeyBundle, ProtocolAddress, PublicKey,
    SignalMessage, SignedPreKeyRecord,
};
use libsignal_protocol_rust::{IdentityKeyStore, SignedPreKeyStore};

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
        // Lets panic messages pass through to the JavaScript console for debugging
        panic::set_hook(Box::new(console_error_panic_hook::hook));

        let mut csprng = OsRng;

        let _source_address = ProtocolAddress::new(source_uuid, DEVICE_ID);
        let registration_id: u32 = csprng.gen();

        let identity_key = IdentityKeyPair::generate(&mut csprng);

        // This struct will hold our session, identity, prekey and sender key stores.
        // TODO: We'll be saving this (encrypted) on the server as we communicate.
        InMemSignalProtocolStore::new(identity_key, registration_id)
            .map(|store| SecureDropSourceSession {
                store,
                registration_id,
            })
            .map_err(|e| e.to_string().into())
    }

    /// Called when we first generate keys prior to initial registration.
    pub fn generate(&mut self) -> Result<JsValue, JsValue> {
        let mut csprng = OsRng;
        let signed_pre_key_pair = KeyPair::generate(&mut csprng);

        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let keypair = self
            .store
            .get_identity_key_pair(None)
            .map_err(|e| e.to_string())?;
        let prekey_signature = keypair
            .private_key()
            .calculate_signature(&signed_pre_key_public, &mut csprng)
            .map_err(|e| e.to_string())?;
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
            &prekey_signature,
        );
        self.store
            .save_signed_pre_key(signed_prekey_id, &signed_prekey_record, None)
            .map_err(|e| e.to_string())?;

        let registration_data = RegistrationBundle {
            signed_prekey_id,
            signed_prekey: hex::encode(signed_pre_key_public),
            //signed_prekey_timestamp: signed_prekey_timestamp.as_secs(),
            signed_prekey_timestamp,
            identity_key: hex::encode(keypair.public_key().serialize()),
            prekey_signature: hex::encode(prekey_signature),
            registration_id: self.registration_id,
        };

        JsValue::from_serde(&registration_data).map_err(|e| e.to_string().into())
    }

    /// TODO: Prevent duplicate registration IDs from source and journalist
    /// (matters on journalist side)
    pub fn process_prekey_bundle(
        &mut self,
        registration_id: u32,
        identity_key: String,
        address: String,
        signed_prekey_id: u32,
        signed_prekey: String,
        signed_prekey_sig: String,
    ) -> Result<bool, JsValue> {

        let mut csprng = OsRng;
        let journo_address = ProtocolAddress::new(address, DEVICE_ID);
        let signed_prekey_bytes = hex::decode(signed_prekey).map_err(|e| e.to_string())?;
        let signed_prekey_sig = hex::decode(signed_prekey_sig).map_err(|e| e.to_string())?;
        let identity_key_bytes = hex::decode(identity_key).map_err(|e| e.to_string())?;
        let identity_key = IdentityKey::decode(&identity_key_bytes).map_err(|e| e.to_string())?;
        let signed_prekey =
            PublicKey::deserialize(&signed_prekey_bytes).map_err(|e| e.to_string())?;
        let pre_key_bundle = PreKeyBundle::new(
            registration_id,
            DEVICE_ID,
            None, // pre key id TK
            None, // pre key TK
            signed_prekey_id,
            signed_prekey,
            signed_prekey_sig,
            identity_key,
        )
        .map_err(|e| e.to_string())?;

        process_prekey_bundle(
            &journo_address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &pre_key_bundle,
            &mut csprng,
            None,
        )
        .map(|_a| true)
        .map_err(|e| e.to_string().into())
    }

    pub fn encrypt(&mut self, address: String, ptext: String) -> Result<String, JsValue> {
        let recipient = ProtocolAddress::new(address, DEVICE_ID);
        message_encrypt(
            &ptext.into_bytes(),
            &recipient,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            None,
        )
        .map(|data| hex::encode(data.serialize()))
        .map_err(|e| e.to_string().into())
    }

    pub fn decrypt(&mut self, address: String, ciphertext: String) -> Result<String, JsValue> {
        let sender = ProtocolAddress::new(address, DEVICE_ID);
        let mut csprng = OsRng;

        let raw_ciphertext = hex::decode(ciphertext).map_err(|e| e.to_string())?;
        // TODO: Allow other message types here
        // &raw_ciphertext[..] because try_from requires &[u8], raw_ciphertext is Vec<u8>
        let message = SignalMessage::try_from(&raw_ciphertext[..]).map_err(|e| e.to_string())?;
        let plaintext = message_decrypt(
            &CiphertextMessage::SignalMessage(message),
            &sender,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &mut self.store.signed_pre_key_store,
            &mut csprng,
            None,
        )
        .map_err(|e| e.to_string())?;
        String::from_utf8(plaintext).map_err(|e| e.to_string().into())
    }
}

// For putting logic when the wasm module is first loaded
#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    Ok(())
}

use wasm_bindgen::prelude::*;
extern crate console_error_panic_hook;
use std::panic;

use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
// use std::time::{SystemTime, UNIX_EPOCH};
use futures::executor::block_on;

use zkgroup::api::ServerPublicParams;
use libsignal_protocol_rust::{
    message_decrypt, message_encrypt, process_prekey_bundle, CiphertextMessage, IdentityKey,
    IdentityKeyPair, InMemSignalProtocolStore, KeyPair, PreKeyBundle, ProtocolAddress, PublicKey,
    SenderCertificate, SignalMessage, SignedPreKeyRecord, IdentityKeyStore, SignedPreKeyStore, sealed_sender_encrypt, sealed_sender_decrypt,
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
    source_uuid: String,
    store: InMemSignalProtocolStore,
    pub registration_id: u32,
    sender_cert: Option<SenderCertificate>,
    server_trust_root: Option<PublicKey>,
    server_public_params: Option<ServerPublicParams>,
}

#[wasm_bindgen]
impl SecureDropSourceSession {
    pub fn new(source_uuid: String) -> Result<SecureDropSourceSession, JsValue> {
        // Lets panic messages pass through to the JavaScript console for debugging
        panic::set_hook(Box::new(console_error_panic_hook::hook));

        let mut csprng = OsRng;

        let _source_address = ProtocolAddress::new(source_uuid.clone(), DEVICE_ID);
        let registration_id: u32 = csprng.gen();

        let identity_key = IdentityKeyPair::generate(&mut csprng);

        // This struct will hold our session, identity, prekey and sender key stores.
        // TODO: We'll be saving this (encrypted) on the server as we communicate.
        InMemSignalProtocolStore::new(identity_key, registration_id)
            .map(|store| SecureDropSourceSession {
                source_uuid,
                store,
                registration_id,
                sender_cert: None,
                server_trust_root: None,
                server_public_params: None,
            })
            .map_err(|e| e.to_string().into())
    }

    /// Called when we first generate keys prior to initial registration.
    pub fn generate(&mut self) -> Result<JsValue, JsValue> {
        let mut csprng = OsRng;
        let signed_pre_key_pair = KeyPair::generate(&mut csprng);

        let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
        let keypair =
            block_on(self.store.get_identity_key_pair(None)).map_err(|e| e.to_string())?;
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
        block_on(
            self.store
                .save_signed_pre_key(signed_prekey_id, &signed_prekey_record, None),
        )
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

    pub fn save_server_params(
        &mut self,
        server_params: String,
    ) -> Result<bool, JsValue> {
        // let server_public_params = ServerPublicParams::deserialize(
        //     .map_err(|e| e.to_string())?,
        // );
        let server_params_bytes = &hex::decode(server_params).map_err(|e| e.to_string())?;
        let server_public_params: zkgroup::api::server_params::ServerPublicParams = match bincode::deserialize(server_params_bytes) {
            Ok(result) => result,
            Err(err) => return Err(err.to_string().into()),
        };
        self.server_public_params = Some(server_public_params);
        Ok(true)
    }

    pub fn get_cert_and_validate(
        &mut self,
        raw_sender_cert: String,
        trust_root: String,
    ) -> Result<bool, JsValue> {
        let sender_cert = SenderCertificate::deserialize(
            &hex::decode(raw_sender_cert).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let trust_root_pubkey =
            PublicKey::deserialize(&hex::decode(trust_root).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let current_timestamp = 105; // TODO
        self.sender_cert = Some(sender_cert.clone());
        self.server_trust_root = Some(trust_root_pubkey);
        sender_cert
            .validate(&trust_root_pubkey, current_timestamp)
            .map(|_a| true)
            .map_err(|e| e.to_string().into())
    }

    // TODO: Currently we only allow a single group per source. In a true multi-tenant scenario
    // we may want to allow a source to have multiple groups if they are corresponding with
    // several organizations using the same source account.
    pub fn create_group(
        &mut self,
        uuids_of_members: String,
    ) {
        let mut csprng = OsRng;
        let randomness: [u8; 32] = csprng.gen();
        let master_key = zkgroup::groups::GroupMasterKey::new(randomness);
        let group_secret_params = zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);
        let group_public_params = group_secret_params.get_public_params();
        let group_id = group_public_params.get_group_identifier();
        // TODO: Put group public params on server along with encrypted uuids
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

        block_on(process_prekey_bundle(
            &journo_address,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &pre_key_bundle,
            &mut csprng,
            None,
        ))
        .map(|_a| true)
        .map_err(|e| e.to_string().into())
    }

    pub fn encrypt(&mut self, address: String, ptext: String) -> Result<String, JsValue> {
        let recipient = ProtocolAddress::new(address, DEVICE_ID);
        block_on(message_encrypt(
            &ptext.into_bytes(),
            &recipient,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            None,
        ))
        .map(|data| hex::encode(data.serialize()))
        .map_err(|e| e.to_string().into())
    }

    pub fn sealed_sender_encrypt(&mut self, address: String, ptext: String) -> Result<String, JsValue> {
        let recipient = ProtocolAddress::new(address, DEVICE_ID);
        let mut csprng = OsRng;
        block_on(sealed_sender_encrypt(
            &recipient,
            &self.sender_cert.as_ref().expect("no sender cert!"),
            &ptext.into_bytes(),
            &mut self.store.session_store,
            &mut self.store.identity_store,
            None,
            &mut csprng,
        ))
        .map(|data| hex::encode(data))
        .map_err(|e| e.to_string().into())
    }

    pub fn decrypt(&mut self, address: String, ciphertext: String) -> Result<String, JsValue> {
        let sender = ProtocolAddress::new(address, DEVICE_ID);
        let mut csprng = OsRng;

        let raw_ciphertext = hex::decode(ciphertext).map_err(|e| e.to_string())?;
        // TODO: Allow other message types here
        // &raw_ciphertext[..] because try_from requires &[u8], raw_ciphertext is Vec<u8>
        let message = SignalMessage::try_from(&raw_ciphertext[..]).map_err(|e| e.to_string())?;
        let plaintext = block_on(message_decrypt(
            &CiphertextMessage::SignalMessage(message),
            &sender,
            &mut self.store.session_store,
            &mut self.store.identity_store,
            &mut self.store.pre_key_store,
            &mut self.store.signed_pre_key_store,
            &mut csprng,
            None,
        ))
        .map_err(|e| e.to_string())?;
        String::from_utf8(plaintext).map_err(|e| e.to_string().into())
    }

    // TODO: Return sender also
    pub fn sealed_sender_decrypt(&mut self, ciphertext: String) -> Result<String, JsValue> {
        let raw_ciphertext = hex::decode(ciphertext).map_err(|e| e.to_string())?;
        let plaintext = block_on(sealed_sender_decrypt(
            &raw_ciphertext,
            &self.server_trust_root.as_ref().expect("no trust root!"),
            101,  // TODO: timestamp
            Some(self.source_uuid.clone()),
            Some(self.source_uuid.clone()),
            DEVICE_ID,
            &mut self.store.identity_store,
            &mut self.store.session_store,
            &mut self.store.pre_key_store,
            &mut self.store.signed_pre_key_store,
            None,
        ))
        .map_err(|e| e.to_string())?;
        String::from_utf8(plaintext.message).map_err(|e| e.to_string().into())
    }
}

// For putting logic when the wasm module is first loaded
#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    Ok(())
}

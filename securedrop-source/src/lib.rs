use wasm_bindgen::prelude::*;
extern crate console_error_panic_hook;
use std::panic;

use rand::rngs::OsRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
// use std::time::{SystemTime, UNIX_EPOCH};
use futures::executor::block_on;
use uuid::Uuid;

use libsignal_protocol_rust::{
    message_decrypt, message_encrypt, process_prekey_bundle, sealed_sender_decrypt,
    sealed_sender_encrypt, CiphertextMessage, IdentityKey, IdentityKeyPair, IdentityKeyStore,
    InMemSignalProtocolStore, KeyPair, PreKeyBundle, ProtocolAddress, PublicKey, SenderCertificate,
    SignalMessage, SignedPreKeyRecord, SignedPreKeyStore,
};
use zkgroup::api::auth::{AuthCredential, AuthCredentialResponse};
use zkgroup::api::ServerPublicParams;
use zkgroup::groups::{GroupMasterKey, GroupPublicParams, GroupSecretParams};

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

#[derive(Serialize, Deserialize)]
pub struct UuidEntry {
    pub string: String,
}

#[derive(Serialize, Deserialize)]
pub struct PublicGroupCreationBundle {
    pub auth_credential_presentation: String,
    pub group_id: String,
    pub group_public_params: String,
    pub group_members: Vec<String>, // Ciphertexts
    pub group_admins: Vec<String>,  // Ciphertexts
}

#[wasm_bindgen]
pub struct SecureDropSourceSession {
    source_uuid: String,
    store: InMemSignalProtocolStore,
    pub registration_id: u32,
    sender_cert: Option<SenderCertificate>,
    server_trust_root: Option<PublicKey>,
    server_public_params: Option<ServerPublicParams>,
    auth_cred: Option<AuthCredential>,
    group_master_key: Option<GroupMasterKey>,
    group_secret_params: Option<GroupSecretParams>,
    group_public_params: Option<GroupPublicParams>,
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
                auth_cred: None,
                group_master_key: None,
                group_secret_params: None,
                group_public_params: None,
            })
            .map_err(|e| e.to_string().into())
    }

    pub fn uuid(&self) -> String {
        self.source_uuid.clone()
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

    pub fn save_auth_credential(&mut self, auth_cred_resp: String) -> Result<bool, JsValue> {
        let auth_cred_bytes = &hex::decode(auth_cred_resp).map_err(|e| e.to_string())?;
        let auth_cred_response: AuthCredentialResponse = match bincode::deserialize(auth_cred_bytes)
        {
            Ok(result) => result,
            Err(err) => return Err(err.to_string().into()),
        };

        let redemption_time = 123456; // TODO, same as server side

        // TODO: return informative Err if UUID does not parse
        let uid = Uuid::parse_str(&self.source_uuid).unwrap();

        // Now verify proof and get AuthCredential
        let auth_credential = match self
            .server_public_params
            .expect("err: no server params available!")
            .receive_auth_credential(*uid.as_bytes(), redemption_time, &auth_cred_response)
        {
            Ok(result) => result,
            Err(_) => return Err("err: invalid AuthCredentialResponse".into()), // TODO: Use ZkGroupError here
        };

        self.auth_cred = Some(auth_credential);
        Ok(true)
    }

    pub fn save_server_params(&mut self, server_params: String) -> Result<bool, JsValue> {
        let server_params_bytes = &hex::decode(server_params).map_err(|e| e.to_string())?;
        let server_public_params: zkgroup::api::server_params::ServerPublicParams =
            match bincode::deserialize(server_params_bytes) {
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

    // Cannot use Vec<String> - see https://github.com/rustwasm/wasm-bindgen/issues/168
    pub fn create_group(
        &mut self,
        uuids_of_members: &JsValue,
        uuids_of_admins: &JsValue,
    ) -> Result<JsValue, JsValue> {
        let uuids_of_members: Vec<UuidEntry> = uuids_of_members.into_serde().unwrap();
        let uuids_of_admins: Vec<UuidEntry> = uuids_of_admins.into_serde().unwrap();

        let mut csprng = OsRng;
        let key_randomness: [u8; 32] = csprng.gen();
        let master_key = zkgroup::groups::GroupMasterKey::new(key_randomness);
        let group_secret_params =
            zkgroup::groups::GroupSecretParams::derive_from_master_key(master_key);
        let group_public_params = group_secret_params.get_public_params();
        let group_id = group_public_params.get_group_identifier();

        self.group_secret_params = Some(group_secret_params);
        self.group_public_params = Some(group_public_params);
        self.group_master_key = Some(master_key);

        let auth_cred = match self.auth_cred {
            Some(result) => result,
            None => return Err("err: no AuthCred found".into()), // TODO: Use ZkGroupError here
        };
        let cred_randomness: [u8; 32] = csprng.gen();
        let auth_credential_presentation = self
            .server_public_params
            .expect("err: no server params available!")
            .create_auth_credential_presentation(cred_randomness, group_secret_params, auth_cred);

        let mut admins = Vec::new();
        for admin in uuids_of_admins.iter() {
            let user = Uuid::parse_str(&admin.string).expect("err: could not parse administrator");
            let ciphertext = group_secret_params.encrypt_uuid(*user.as_bytes());
            admins.push(hex::encode(&bincode::serialize(&ciphertext).unwrap()));
        }

        let mut members = Vec::new();
        for member in uuids_of_members.iter() {
            let user = Uuid::parse_str(&member.string).expect("err: could not parse member");
            let ciphertext = group_secret_params.encrypt_uuid(*user.as_bytes());
            members.push(hex::encode(&bincode::serialize(&ciphertext).unwrap()));
        }

        let group_creation_data = PublicGroupCreationBundle {
            auth_credential_presentation: hex::encode(
                &bincode::serialize(&auth_credential_presentation).unwrap(),
            ),
            group_id: hex::encode(group_id),
            group_public_params: hex::encode(&bincode::serialize(&group_public_params).unwrap()),
            group_members: members,
            group_admins: admins,
        };
        JsValue::from_serde(&group_creation_data).map_err(|e| e.to_string().into())
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

    pub fn sealed_sender_encrypt(
        &mut self,
        address: String,
        ptext: String,
    ) -> Result<String, JsValue> {
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

    // We pack up the group key and send it to new group participants.
    pub fn sealed_send_encrypted_group_key(&mut self, address: String) -> Result<String, JsValue> {
        let group_key = match self.group_master_key {
            Some(result) => result,
            None => return Err("err: no GroupMasterKey found".into()), // TODO: Use ZkGroupError here
        };

        let recipient = ProtocolAddress::new(address, DEVICE_ID);
        let mut csprng = OsRng;
        block_on(sealed_sender_encrypt(
            &recipient,
            &self.sender_cert.as_ref().expect("no sender cert!"),
            &bincode::serialize(&group_key).unwrap(),
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
            101, // TODO: timestamp
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

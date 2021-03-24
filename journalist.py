import json
import os
import requests
import time
from uuid import UUID

PAUSE = 2

from signal_protocol import address, curve, identity_key, storage, sealed_sender, session, session_cipher, state, protocol
from signal_groups.api.auth import AuthCredential, AuthCredentialResponse
from signal_groups.api.server_params import ServerPublicParams
from signal_groups.api.groups import GroupMasterKey, GroupSecretParams

username = os.getenv("SECUREDROP_JOURNALIST_USERNAME", "journalist")
passphrase = os.getenv("SECUREDROP_JOURNALIST_PASSPHRASE", "this dont matter")
totp = os.getenv("SECUREDROP_JOURNALIST_TOTP", "123666")

# Root endpoint
resp = requests.get('http://127.0.0.1:8081/api/v2/')
print(resp, resp.text)
time.sleep(PAUSE)

# Login
resp = requests.post('http://127.0.0.1:8081/api/v2/token',
                     data=json.dumps({"username": username, "passphrase": passphrase, "one_time_code": totp}))
token = resp.json()['token']
journalist_uuid = resp.json()['journalist_uuid']
print("we've logged in and gotten our API token!")
time.sleep(PAUSE)

auth_headers = {
    "Authorization": f"Token {token}",
    "Content-Type": "application/json",
    "Accept": "application/json",}

print("generating required key material for Signal registration...")
DEVICE_ID = 1 # Unused but required field in the protocol
registration_id = 666
journalist_address = address.ProtocolAddress(journalist_uuid, DEVICE_ID)

# Store this somewhere
identity_key_pair = identity_key.IdentityKeyPair.generate()

# Store should be persisted to disk
store = storage.InMemSignalProtocolStore(
        identity_key_pair, registration_id
    )
# Store this somewhere
signed_pre_key_id = 232
signed_pre_key_pair = curve.KeyPair.generate()
signed_pre_key_public = signed_pre_key_pair.public_key().serialize()
signed_pre_key_signature = (
        store.get_identity_key_pair()
        .private_key()
        .calculate_signature(signed_pre_key_public)
    )
signed_prekey_timestamp = int(time.time())

# prekey = state.PreKeyRecord(pre_key_id, pre_key_pair)
# store.save_pre_key(pre_key_id, prekey)

signed_prekey = state.SignedPreKeyRecord(
    signed_pre_key_id,
    signed_prekey_timestamp,
    signed_pre_key_pair,
    signed_pre_key_signature,
)
store.save_signed_pre_key(signed_pre_key_id, signed_prekey)

print("done! now attempting registration with the server...")
resp = requests.post('http://127.0.0.1:8081/api/v2/register',
                     data=json.dumps(
                         {"signed_prekey_id": signed_pre_key_id,
                          "signed_prekey": signed_pre_key_public.hex(),
                          "signed_prekey_timestamp": signed_prekey_timestamp,
                          "identity_key": identity_key_pair.public_key().serialize().hex(),
                          "prekey_signature": signed_pre_key_signature.hex(),
                          "registration_id": registration_id }),
                     headers=auth_headers)
print(resp, resp.text)
time.sleep(PAUSE)

print("getting public parameters..")
resp = requests.get('http://127.0.0.1:8081/api/v2/server_params',
                     headers=auth_headers)
print(resp, resp.text)
raw_server_public_params = resp.json().get("server_public_params")
server_public_params = ServerPublicParams.deserialize(bytes.fromhex(raw_server_public_params))

print("getting sender certificate...")
resp = requests.get('http://127.0.0.1:8081/api/v2/sender_cert',
                     headers=auth_headers)
print(resp, resp.text)
raw_sender_cert = resp.json().get("sender_cert")
sender_cert = sealed_sender.SenderCertificate.deserialize(bytes.fromhex(raw_sender_cert))
trust_root = resp.json().get("trust_root")
trust_root_pubkey = curve.PublicKey.deserialize(bytes.fromhex(trust_root))
current_timestamp = 100

print("getting auth credential...")
resp = requests.get('http://127.0.0.1:8081/api/v2/auth_credential',
                     headers=auth_headers)
print(resp, resp.text)
raw_auth_credential = resp.json().get("auth_credential")
auth_credential_resp = AuthCredentialResponse.deserialize(bytes.fromhex(raw_auth_credential))
redemption_time = 123456  # TODO, same as server side  # TODO: this is M4 but not used in the proof?
uid = UUID(journalist_uuid).bytes
auth_credential = server_public_params.receive_auth_credential(uid, redemption_time, auth_credential_resp)

# Ensure certificate is still valid
sender_cert.validate(trust_root_pubkey, current_timestamp)
print("sender cert is valid!")

time.sleep(PAUSE)

print("waiting for messages from sources")
while True:
    time.sleep(PAUSE)

    print("lets see if I have any messages...")
    resp = requests.get(f'http://127.0.0.1:8081/api/v2/messages',
                        headers=auth_headers)
    print(resp, resp.text)

    raw_message = resp.json().get("message", None)
    message_uuid = resp.json().get("message_uuid", None)

    if not raw_message:
        continue

    current_timestamp = 100
    message = sealed_sender.sealed_sender_decrypt(
        bytes.fromhex(raw_message),
        trust_root_pubkey,
        current_timestamp,
        journalist_uuid,
        journalist_uuid,
        DEVICE_ID,
        store,
    )
    # We get sender from within the envelope instead of from what is stored on the server
    source_uuid = message.sender_uuid()
    source_address = address.ProtocolAddress(source_uuid, DEVICE_ID)

    print(message.message().decode('utf8'))
    time.sleep(PAUSE)

    print("confirming receipt and successful decryption of message")
    resp = requests.post(f'http://127.0.0.1:8081/api/v2/messages/confirmation/{message_uuid}',
                          headers=auth_headers)
    print(resp, resp.text)
    time.sleep(PAUSE)

    journo_response = b"wellllll howdy doody! please tell me more"
    print(f'now responding to source... sending {journo_response}')

    sealed_sender_message = sealed_sender.sealed_sender_encrypt(
        source_address, sender_cert, journo_response, store
    )
    time.sleep(PAUSE)

    print("sending message!!!!..")
    resp = requests.post(f'http://127.0.0.1:8081/api/v2/sources/{source_uuid}/messages',
                        data=json.dumps(
                            {"message": sealed_sender_message.hex()}),
                        headers=auth_headers)
    print(resp, resp.text)
    time.sleep(PAUSE)

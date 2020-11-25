import json
import requests
import time

PAUSE = 2

from signal_protocol import address, curve, identity_key, storage, session, session_cipher, state, protocol

username = "journalist"
passphrase = "this dont matter"
totp = "123666"

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


print("waiting for messages from sources")
while True:
    time.sleep(PAUSE)

    print("lets see if I have any messages...")
    resp = requests.get(f'http://127.0.0.1:8081/api/v2/messages',
                        headers=auth_headers)
    print(resp, resp.text)

    message = resp.json().get("message", None)
    source_uuid = resp.json().get("source_uuid", None)

    if not message:
        continue

    # Else, we have a message.
    source_address = address.ProtocolAddress(source_uuid, DEVICE_ID)
    # TODO: Clients need to try_from using the appropriate message type
    incoming_message = protocol.PreKeySignalMessage.try_from(bytes.fromhex(message))

    plaintext = session_cipher.message_decrypt(
        store, source_address, incoming_message
    )

    print(plaintext.decode('utf8'))

    # SECOND ROUNDTRIP, DELETE

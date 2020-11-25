import json
import requests
import time

PAUSE = 2

from signal_protocol import address, curve, identity_key, state, storage, session, session_cipher

# Copy a source codename from the dev console
passphrase = "strum snowcap monotype unstirred setback hardened unless font"

# Root endpoint
resp = requests.get('http://127.0.0.1:8080/api/v2/')
print(resp, resp.text)
time.sleep(PAUSE)

# Login (temp)
resp = requests.post('http://127.0.0.1:8080/api/v2/token',
                     data=json.dumps({"passphrase": passphrase}))
print(resp)
token = resp.json()['token']
source_uuid = resp.json()['source_uuid']
print("we've logged in to the source API and gotten our API token!")
time.sleep(PAUSE)

auth_headers = {
    "Authorization": f"Token {token}",
    "Content-Type": "application/json",
    "Accept": "application/json",}

print("generating required key material for Signal registration...")
DEVICE_ID = 1 # Unused but required field in the protocol
registration_id = 667
source_address = address.ProtocolAddress(source_uuid, DEVICE_ID)

# Store this somewhere
identity_key_pair = identity_key.IdentityKeyPair.generate()

# Store should be persisted to disk
store = storage.InMemSignalProtocolStore(
        identity_key_pair, registration_id
    )
# Store this somewhere
signed_pre_key_pair = curve.KeyPair.generate()
signed_pre_key_public = signed_pre_key_pair.public_key().serialize()
signed_pre_key_signature = (
        store.get_identity_key_pair()
        .private_key()
        .calculate_signature(signed_pre_key_public)
    )
signed_prekey_timestamp = int(time.time())

signed_pre_key_id = 2125
print("done! now attempting registration with the server...")
resp = requests.post('http://127.0.0.1:8080/api/v2/register',
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


# Get SecureDrop group members, we'll message the members in the default group.
resp = requests.get('http://127.0.0.1:8080/api/v2/groups',
                     headers=auth_headers)
journalist_uuid = resp.json()["default"]
print(resp, resp.text)
time.sleep(PAUSE)


# Get prekey bundles in preparation for session setup.
resp = requests.get(f'http://127.0.0.1:8080/api/v2/journalists/{journalist_uuid}/prekey_bundle',
                     headers=auth_headers)
journalist_prekey = resp.json()
print(resp, resp.text)
time.sleep(PAUSE)


# Prepare signal message and send
# Now in a real situation with groups, this would be "for member in group:"
journo_signed_prekey = curve.PublicKey.deserialize(bytes.fromhex(journalist_prekey["signed_prekey"]))
journo_identitykey = identity_key.IdentityKey(bytes.fromhex(journalist_prekey["identity_key"]))
journalist_address = address.ProtocolAddress(journalist_uuid, DEVICE_ID)
new_pre_key_bundle = state.PreKeyBundle(
        journalist_prekey["registration_id"],
        DEVICE_ID,
        None,  # for OT prekey, TODO
        None,  # for OT prekey, TODO
        journalist_prekey["signed_prekey_id"],
        journo_signed_prekey,
        bytes.fromhex(journalist_prekey["prekey_signature"]),
        journo_identitykey,
)

session.process_prekey_bundle(
    journalist_address,
    store,
    new_pre_key_bundle,
)

original_message = "Hello I do declare I have some Interesting Deets about a Bad Thing"

outgoing_message = session_cipher.message_encrypt(
    store, journalist_address, original_message
)

print("message baking complete! now sending to my friend via the SecureDrop Server")
resp = requests.post(f'http://127.0.0.1:8080/api/v2/journalists/{journalist_uuid}/messages',
                     data=json.dumps(
                         {"message": outgoing_message.serialize().hex()}),
                     headers=auth_headers)
print(resp, resp.text)
time.sleep(PAUSE)

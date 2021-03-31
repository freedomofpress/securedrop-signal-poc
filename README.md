# securedrop-e2e
prototype source + journalist clients for securedrop

⚠️ **these are prototypes for discussion only and are NOT for production use** ⚠️

## How to demo

There are Python clients in `journalist.py` (user `journalist`) and `journalist2.py` (user `dellsberg`) to demo e2ee comms through the server. To modify that Python client, simply install `requirements.txt`.

To try out and demo e2e encryption, you should:

0. Setup the `securedrop-source` crate as described at the bottom of this readme.

1. Then run this server branch which provide the v2 APIs required: https://github.com/redshiftzero/securedrop/signal-proto

2. Once the server is running, set the OTP token and password in the top of `journalist.py`. Then start `journalist.py`:

```
python3 journalist.py
```

This will first perform signal registration, then wait for messages for sources. In another Terminal, Do the same with `journalist2.py` (this simulates a conversation between one source and multiple journalists).

3. Then visit the source interface and create an account. When you login, it will perform signal registration without interaction from the user.

4. Send a message to a journalist, then wait for responses. When the journalists respond (done in the `journalist*.py` scripts), without interaction from the user, the journalist message should appear decrypted.

Note that the source sessions currently do not persist, i.e. this demo only works on first login (we'd need some logic to store the session data either locally in the browser or encrypted on the server). If you try it on subsequent logins, you'll get an error in the console indicating the session is not found.

In a "real" deployment, the logic in `journalist*.py` would run as part of `securedrop-client`.

## securedrop-source crate

`securedrop-source` is a Rust crate that provides a high-level wrapper for the cryptographic operations required to register as a Signal client and encrypt and decrypt messages. It compiles to WebAssembly for use on the SecureDrop source interface to enable client-side cryptographic operations.

### Development

You will need a rust toolchain installed on your system to modify the securedrop-source crate.

To compile to wasm and generate glue js for the source interface, one should in the `securedrop-source` directory build with [`wasm-pack`](https://github.com/rustwasm/wasm-pack):

```
wasm-pack build --target web
```

This produces a `pkg` directory with the compiled wasm and js (along with other files that are not strictly required). The two files you want are:

```
./pkg/securedrop_source.js
./pkg/securedrop_source_bg.wasm
```

You will need to copy the js and wasm files over to the server dev container. The easiest way to do this is to set `$SECUREDROP_SERVER` to the root of the git tree containing your SecureDrop checkout. Then:

```
cp pkg/securedrop_source.js $SECUREDROP_SERVER/securedrop/static/js/
cp pkg/securedrop_source_bg.wasm $SECUREDROP_SERVER/securedrop/static/js/
```

You can now set up event handlers and other logic as you see fit using JS on the source interface.

# securedrop-e2e
prototype source + journalist clients for securedrop

⚠️ **these are prototypes for discussion only and are NOT for production use** ⚠️

## Run the demo

There are Python clients in `journalist.py` (user `journalist`) and `journalist2.py` (user `dellsberg`) to demo e2e communications through the server.
To modify that Python client, simply install `requirements.txt`.

To try out e2e encryption, you should:

0. Setup the `securedrop-source` crate as described at the bottom of this readme.
1. In the main `securedrop` repo, check out the [`signal-proto`](https://github.com/freedomofpress/securedrop/tree/signal-proto.) branch,
   which provides the required v2 APIs.
   (We assume you have a successfully running development environment for SecureDrop.
   See the docs here for more.)
1. Run `make dev`.
1. Once the server is running, set the OTP token and password in the top of `journalist.py`.
1. Start `journalist.py`:

   ```
   python3 journalist.py
   ```

   This will first perform signal registration, then wait for messages for sources.
1. In another Terminal, do the same with `journalist2.py`.
   This simulates a conversation between one source and multiple journalists.
1. Then visit the source interface and create an account.
   When you login, it will perform signal registration without interaction from the user.
1. Send a message to a journalist, then wait for responses.
   When the journalists respond (done in the `journalist*.py` scripts),
   without interaction from the user, the journalist message should appear decrypted.

Note that the source sessions currently do not persist, i.e. this demo only works on first login (we'd need some logic to store the session data either locally in the browser or encrypted on the server). If you try it on subsequent logins, you'll get an error in the console indicating the session is not found.

In a "real" deployment, the logic in `journalist*.py` would run as part of `securedrop-client`.

## v1 message format

Messages are JSON with allowed keys: `mtype`, (optional) `msg`, (optional) `group_id`.
Group messages _must_ have `group_id` (`[u8; 32]`).

The `mtype` field is a `u8` with the following meaning:
* 0: reserved.
* 1: `SD_GROUP_MANAGEMENT_START`. Group creation message. `group_id` contains the group identifier (derived from the public parameters). `msg` field contains the `GroupMasterKey`.
* 2-10s: reserved for `SD_GROUP_MANAGEMENT*` messages.
* 11: `SD_GROUP_MESSAGE`. `group_id` contains the group identifier (derived from the public parameters). `msg` field contains the message body to be displayed to the user.
* 12-*: available.

## securedrop-source crate

`securedrop-source` is a Rust crate that provides a high-level wrapper for the cryptographic operations required to register as a Signal client and encrypt and decrypt messages. It compiles to WebAssembly for use on the SecureDrop source interface to enable client-side cryptographic operations.

To view the docs for this crate:

```
cargo doc --open
```

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

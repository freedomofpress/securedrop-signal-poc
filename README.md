# securedrop-e2e

_prototype source + journalist clients for SecureDrop_

⚠️ **These are prototypes for discussion only and are NOT for production use** ⚠️

## Run the demo

There are Python clients in `journalist.py` (user `journalist`) and `journalist2.py` (user `dellsberg`) to demo e2e communications through the server.

To run or modify these Python clients, simply run:

```sh-session
$ make venv
[...]
#################
Make sure to run: source .venv/bin/activate
$ source .venv/bin/activate
```

To try out e2e encryption, complete the following steps:

0. Setup the `securedrop-source` crate as [described below](#securedrop-source-crate).
1. In the main `securedrop` repo, check out the [`signal-proto-focal`](https://github.com/freedomofpress/securedrop/tree/signal-proto-focal) branch,
   which provides the required v2 APIs.
   (We assume you have previously run development environment for SecureDrop.
   See the [SecureDrop developer documentation ](https://docs.securedrop.org/en/stable/development/setup_development.html) for more.)
1. Run `make dev` to start the SecureDrop developement server.
1. Once the server is running, set the `SECUREDROP_JOURNALIST_PASSPHRASE` and `SECUREDROP_JOURNALIST_TOTP` environment variables to the passphrase and totp secret values used in the dev environment (see https://github.com/freedomofpress/securedrop-e2e/blob/main/journalist.py#L14-L16).
1. Start `journalist.py`:

   ```
   python3 journalist.py
   ```

   This will first perform signal registration, then wait for messages for sources.
1. In another terminal, follow the steps above with `journalist2.py`.
   This simulates a conversation between one source and multiple journalists.
1. Visit the source interface and create an account.
   When you login, it will perform Signal registration without interaction from the user.
1. Send a message to a journalist, then wait for responses.
   When the journalists respond (done in the `journalist*.py` scripts),
   without interaction from the user, the journalist message should appear decrypted.

Note that the source sessions currently do not persist, i.e. this demo only works on first login (we'd need some logic to store the session data either locally in the browser or encrypted on the server). If you try it on subsequent logins, you'll get an error in the console indicating the session is not found.

In a "real" deployment, the logic in `journalist*.py` would run as part of `securedrop-client`.

## v1 message format

Messages are JSON with the following keys:

- `mtype` (optional)
- `msg` (optional)
- `group_id`.

Group messages _must_ have `group_id` (`[u8; 32]`).

The `mtype` field is a `u8` with the following meanings:

| #        | Meaning                     | Description                                                                                                                                       |
|:---------|:----------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| `0`      | Reserved.                   |                                                                                                                                                   |
| `1`      | `SD_GROUP_MANAGEMENT_START` | Group creation message. `group_id` contains the group identifier (derived from the public parameters). `msg` field contains the `GroupMasterKey`. |
| `2`-`10` | `SD_GROUP_MANAGEMENT*`      | Reserved for group management messages.                                                                                                           |
| `12`-    | Available.                  |                                                                                                                                                   |

## `securedrop-source` crate

`securedrop-source` is a Rust crate that provides a high-level wrapper for the cryptographic operations
required to register as a Signal client and encrypt and decrypt messages.
It compiles to WebAssembly for use on the SecureDrop source interface to enable client-side cryptographic operations.

To view the docs for this crate:

```
cargo doc --open
```

### Development

You will need a Rust toolchain installed on your system to work on the `securedrop-source` crate.
To compile to Wasm and generate glue JS for the source interface,
build the `securedrop-source` directory with [`wasm-pack`](https://github.com/rustwasm/wasm-pack):

```
make build
```

That command will:

  1. Lint and run tests
  2. Compile to Wasm and generate glue JS for the Source Interface
  3. Copy the JS files to SecureDrop repo at `../securedrop/`

The `pkg` directory within the securedrop-source crate contains the Wasm and JS,
along with other files that are not strictly required. The two files you want are:

```
./securedrop-source/pkg/securedrop_source.js
./securedrop-source/pkg/securedrop_source_bg.wasm
```

You can now set up event handlers and other logic as you see fit using JS on the source interface.

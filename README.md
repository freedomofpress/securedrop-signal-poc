# securedrop-e2e
prototype source + journalist clients for securedrop

## Python clients

Python clients in `journalist.py` and `source.py` demo e2e comms through the server. Clients test source-initiated communication (i.e. journalist GET prekey bundle endpoint is not used).

To modify these Python clients, simply install `requirements.txt`.

To try out and run these clients, you should run this server branch which provide the v2 APIs required: https://github.com/redshiftzero/securedrop/signal-proto

Once the server is running, set the OTP token and password in the top of `journalist.py`. Then start `journalist.py`:

```
python3 journalist.py
```

This will first perform signal registration, then wait for messages for sources.

Then update `source.py` with the codename of an existing source, and start the source script:

```
python3 source.py
```

This script will also perform signal registration, send a message to a journalist, then wait for responses. When the journalists responds (done in the `journalist.py` script), we decrypt.

In a "real" deployment, we'd integrate the logic in `journalist.py` into `securedrop-client`. The logic in `source.py` would need to be ported to JS/wasm such that it runs in Tor Browser (see below).

## securedrop-source crate

`securedrop-source` is a Rust crate that provides a high-level wrapper for the cryptographic operations required to register as a Signal client and encrypt and decrypt messages. It compiles to WebAssembly for use on the SecureDrop source interface to enable client-side cryptographic operations.

### Development

You will need a rust toolchain installed on your system to modify the securedrop-source crate.

To compile to wasm and generate glue js for the source interface, one should:

```
wasm-pack build --target web
```

This produces a `pkg` directory with the compiled wasm and js (along with other files that are not strictly required). The two files you want are:

```
./pkg/securedrop_source.js
./pkg/securedrop_source_bg.wasm
```

You can serve immediately to test using `index.html`:

```
python3 -m http.server
```

You will need to copy the js and wasm files over to the server dev container. The easiest way to do this is to set `$SECUREDROP_SERVER` to the root of the git tree containing your SecureDrop checkout. Then:

```
cp pkg/securedrop_source.js $SECUREDROP_SERVER/securedrop/static/js/
cp pkg/securedrop_source_bg.wasm $SECUREDROP_SERVER/securedrop/static/js/
```

You can now set up event handlers and other logic as you see fit using JS on the source interface.

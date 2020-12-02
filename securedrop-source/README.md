`securedrop-source` is a Rust crate that provides a high-level wrapper for the cryptographic operations required to register as a Signal client and encrypt and decrypt messages. It compiles to WebAssembly for use on the SecureDrop source interface to enable client-side cryptographic operations.

## Development

You will need a rust toolchain installed on your system to modify the securedrop-source crate.

To compile to wasm and generate glue js for the source interface, one should:

```
wasm-pack build --target web
```

This produces a `pkg` directory with the compiled wasm and js (along with other files that are not strictly required):

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
cp pkg/securedrop_source $SECUREDROP_SERVER/securedrop/static/js/
cp pkg/securedrop_source_bg.wasm $SECUREDROP_SERVER/securedrop/static/js/
```

You can now set up event handlers and other logic as you see fit using JS on the source interface.

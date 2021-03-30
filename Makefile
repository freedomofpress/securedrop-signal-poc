DEFAULT_GOAL: all

all: lint test build deploy-dev

.PHONY: build
build:
	wasm-pack build --target web securedrop-source

.PHONY: deploy-dev
deploy-dev:
	@test -d ../securedrop/ || { echo "ERROR: Missing securedrop repo at ../securedrop/" && exit 1 ; }
	@cp -v -t ../securedrop/securedrop/static/js/ \
		securedrop-source/pkg/securedrop_source.js \
		securedrop-source/pkg/securedrop_source_bg.wasm

.PHONY: lint
lint:
	cargo fmt --manifest-path securedrop-source/Cargo.toml -- --check
	cargo clippy --manifest-path securedrop-source/Cargo.toml

.PHONY: test
test:
	cargo test --manifest-path securedrop-source/Cargo.toml

#!/bin/bash

# Build a custom imix binary for rake
cd implants/imixv2
export IMIX_CALLBACK_URI="http://localhost:8000?interval=1"
export IMIX_SERVER_PUBKEY=`curl -qk http://localhost:8000/status`
export IMIX_RETRY_INTERVAL=0
cargo build --target x86_64-unknown-linux-musl --bin imixv2
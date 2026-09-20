#!/bin/sh
set -eu
cd -- "$(dirname -- "$0")"
if [ "$(uname -s)" != Linux ]; then
    echo 'Run this script on Linux.' >&2
    exit 1
fi
case "$(uname -m)" in
    x86_64) target=x86_64-unknown-linux-gnu ;;
    aarch64) target=aarch64-unknown-linux-gnu ;;
    *) echo 'Supported Linux build hosts: x86_64 and aarch64.' >&2; exit 1 ;;
esac
cargo fmt --all -- --check
cargo clippy --locked --all-targets --target "$target" -- -D warnings
cargo test --locked --release --target "$target"
cargo build --locked --release --target "$target"
mkdir -p "dist/$target"
cp "target/$target/release/xorbox" "dist/$target/xorbox"
cp README.md "dist/$target/README.md"
printf 'Built dist/%s/xorbox\n' "$target"

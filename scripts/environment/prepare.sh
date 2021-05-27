#! /usr/bin/env bash
set -e -o verbose

PATH=$PATH:$HOME/.cargo/bin

rustup toolchain install "$(cat rust-toolchain)"
rustup default "$(cat rust-toolchain)"
rustup component add rustfmt
rustup component add clippy
rustup target add wasm32-wasi
rustup run stable cargo install cargo-deb --version 1.29.2
rustup run stable cargo install cross --version 0.2.1

# If we're running under CI (GH Actions), and we've been instructed to add it,
# set VECTOR_BUILD_DESC to add in pertinent build information.  We typically only
# enable this when generating binaries that will be in the hands of users so that
# know which Git commit they were built from, etc.
VECTOR_USE_BUILD_DESC=${VECTOR_USE_BUILD_DESC:-"false"}
if [[ -f "${GITHUB_ENV}" && "${VECTOR_USE_BUILD_DESC}" == "true" ]]; then
    GIT_SHA=$(git rev-parse --short HEAD)
    CURRENT_DATE=$(date +%Y-%m-%d)
    echo VECTOR_BUILD_DESC="${GIT_SHA} ${CURRENT_DATE}" >> $GITHUB_ENV
fi

cd scripts
bundle update --bundler
bundle install
cd ..

sudo npm -g install markdownlint-cli

pip3 install jsonschema==3.2.0
pip3 install remarshal==0.11.2

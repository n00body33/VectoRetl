FROM ghcr.io/cross-rs/aarch64-unknown-linux-gnu:0.2.4

COPY bootstrap-ubuntu.sh .
RUN ./bootstrap-ubuntu.sh

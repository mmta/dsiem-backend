FROM messense/rust-musl-cross:x86_64-musl AS builder
COPY . .
WORKDIR /home/rust/src/ctx
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:edge
WORKDIR /dsiem
COPY --from=builder /home/rust/src/ctx/target/x86_64-unknown-linux-musl/release/dsiem-backend-rs ./dsiem
RUN mkdir -p configs
VOLUME ["/dsiem/logs", "/dsiem/configs"]
EXPOSE 8080
CMD ["/dsiem/dsiem", "serve" ]

FROM messense/rust-musl-cross:x86_64-musl AS builder
COPY . .
WORKDIR /home/rust/src/ctx
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:edge

RUN apk -U upgrade && apk add bash ca-certificates && rm -rf /var/cache/apk/*

WORKDIR /dsiem
COPY --from=builder /home/rust/src/ctx/target/x86_64-unknown-linux-musl/release/dsiem-backend-rs ./dsiem
RUN mkdir -p configs

# s6-overlay
ADD https://github.com/just-containers/s6-overlay/releases/download/v1.20.0.0/s6-overlay-amd64.tar.gz /tmp/
RUN tar xzf /tmp/s6-overlay-amd64.tar.gz -C /

ENV TERM xterm-256color
# copy s6files and set default to expose all container env to the target app
ADD s6files /etc/
ENV S6_KEEP_ENV 1

# fail container if init scripts failed
ENV S6_BEHAVIOUR_IF_STAGE2_FAILS 2
VOLUME ["/dsiem/logs", "/dsiem/configs" ]
ENTRYPOINT [ "/init"]

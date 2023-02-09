#!/bin/bash

exec docker run --rm -it -v $(pwd):/home/rust/src messense/rust-musl-cross:x86_64-musl cargo build --release

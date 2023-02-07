# Dsiem backend

This is an implementation of [Dsiem](https://github.com/defenxor/dsiem) backend-only mode in Rust. 

# Differences

Compared to Dsiem binary from the main repo, this binary currently:

- Doesn't implement vulnerability check plugin, only intel check plugin is available.
- Doesn't use a custom queue, and because of that, doesn't currently implement watchdog (regular stats printout to stdout).
- Integrate `backlog` and `alarm` to one struct to reduce copy operations.
- More simplified use of channels (with the assistance from async), particularly for backpressure control and backlog deletion.
- Overall simpler structure and easier to understand, partly because of the reduced features.


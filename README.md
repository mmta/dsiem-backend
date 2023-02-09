# Dsiem backend

This is an implementation of [Dsiem](https://github.com/defenxor/dsiem) backend-only mode in Rust. 

# Differences

Compared to Dsiem binary from the main repo, this binary currently:

- Doesn't implement vulnerability check plugin, only intel check plugin is available.
- Integrate `backlog` and `alarm` to one struct to reduce data duplication.
- More simplified use of channels (with the assistance from async), particularly for backpressure control and backlog deletion.
- Overall simpler structure and easier to understand, partly because of the reduced features.

# Dsiem backend

[![CI](https://github.com/mmta/dsiem-backend/actions/workflows/publish.yml/badge.svg)](https://github.com/mmta/dsiem-backend/actions/workflows/publish.yml) [![codecov](https://codecov.io/gh/mmta/dsiem-backend/branch/master/graph/badge.svg?token=GFF0LCZDO2)](https://codecov.io/gh/mmta/dsiem-backend)

An implementation of [Dsiem](https://github.com/defenxor/dsiem) backend-only mode in Rust. The goals are:

- Evaluate different runtimes (e.g. go vs tokio) specific to Dsiem use case.
- Identify optimization opportunities for the code in Dsiem main repo.

## Usage

For docker/container environment: Just replace your existing backend image location from `defenxor/dsiem` to `mmta/dsiem-backend`, all backend related environment variables are accepted and should work as intended.

For non container environment:
- Build the binary with `cargo build --release`.
- Review the startup parameters by running the binary with `--help`:
    ```shell
    ./dsiem-backend --help
    ./dsiem-backend serve --help
    ```
- And adjust your parameters accordingly. At minimum, `serve` requires you to define `-f` (frontend URL) `--msq` (NATS url), and `-n` (backend name) parameters.

## Documentation

Refer to the [documentation](https://github.com/defenxor/dsiem/tree/master/docs) in dsiem main repo.

## Differences with dsiem main repo binary

Compared to Dsiem in the main repo, this binary currently:

- Doesn't implement vulnerability check plugin, only intel check plugin is available.
- Integrate `backlog` and `alarm` to one struct to reduce data duplication.
- More simplified use of channels (with the assistance from async), particularly for backpressure control, backlog deletion, and stats reporting.
- Overall simpler structure and easier to understand, partly because of the reduced features.
- Doesn't default to use JSON-lines log output (enable through `-j` parameter or `DSIEM_JSON=true` env. variable).
- Has no support for Elastic APM.
- Has less test coverage, and has not been thoroughly tested in production environment (this may improve).


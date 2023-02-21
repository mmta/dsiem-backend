# Dsiem backend

[![CI](https://github.com/mmta/dsiem-backend/actions/workflows/publish.yml/badge.svg)](https://github.com/mmta/dsiem-backend/actions/workflows/publish.yml) 
[![codecov](https://codecov.io/gh/mmta/dsiem-backend/branch/master/graph/badge.svg?token=GFF0LCZDO2)](https://codecov.io/gh/mmta/dsiem-backend)

An implementation of [Dsiem](https://github.com/defenxor/dsiem) backend-only mode in Rust. The goals are:

- Evaluate different runtimes (e.g. go vs tokio) specific to Dsiem use case.
- Identify optimization opportunities for the code in Dsiem main repo.

## Usage

For docker/container environment: Just replace your existing backend image location from `defenxor/dsiem` to `mmta/dsiem-backend`, 
all backend related environment variables are accepted and should work as intended.

For non container environment:
- Build the binary with `cargo build --release`.
- Review the startup parameters by running the binary with `--help`:
    ```shell
    ./dsiem-backend --help
    ./dsiem-backend serve --help
    ```
- And adjust your parameters accordingly. At minimum, `serve` requires you to define `-f` (frontend URL) `--msq` (NATS url), 
  and `-n` (backend name) parameters.

## Documentation

Refer to the [documentation](https://github.com/defenxor/dsiem/tree/master/docs) in dsiem main repo.

## Differences with dsiem main repo binary

Compared to Dsiem in the main repo, this binary currently:

- Support saving backlogs to disk before exiting, and reloading them after restart (controlled by `--reload-backlogs` flag, see below for more details).
- Has no support for Elastic APM.
- Requires all directives to be loaded without error during startup. The behaviour of the main repo binary which tries to fix minor errors,
  and skip loading (with a warning) directives that has major errors, is only practical during initial migration from OSSIM.
- Doesn't default to use JSON-lines log output (enable through `-j` parameter or `DSIEM_JSON=true` env. variable).
- Integrate `backlog` and `alarm` to one struct to reduce data duplication.
- More simplified use of channels (with the assistance from async), particularly for backpressure control, backlog deletion, and stats reporting.
- Overall simpler structure and easier to understand, partly because of the reduced features.
- Has not been thoroughly tested in production environment (this may improve).

## Saving and reloading backlogs on restart

If `--reload-backlogs` flag or `DSIEM_RELOAD_BACKLOG` environment variable is set to `true` (which is the default), then existing backlogs 
will be saved to `/logs/backlogs/{directive_id}.json` when dsiem-backend shuts down, and will be reloaded on the next run. The goal of this feature is
to reduce the number of alarms that are recreated during configuration changes (directives, assets, etc.).

A couple of notes on this feature:

- A saved backlog that has a different title than the directive will be discarded. This is to prevent manager from loading a wrong backlog for a directive, 
  which could happen if there's a change in directive ID assignment during down time.

- Backlogs loaded from disk will continue to use their previous rules, so any changes made to the directive rules during down time will only apply to new backlogs.
  Modify `/logs/backlogs/{directive_id}.json` during down time if there is a need to immediately apply updated rules to saved backlogs on next run, 
  or just delete the file to discard all saved backlogs.

- All `/logs/backlogs/{directive_id}.json` files will be deleted on the next run regardless of whether the backlogs therein were successfully loaded or not. This is to prevent
  potential content error affecting the backend startup process.

- Saving is activated upon receiving `SIGTERM` signal. That includes commands like `docker restart` and `kill {PID}`. By contrast, `kill -9 {PID}` or any similar command which sends `SIGKILL` instead of `SIGTERM`, will not activate saving backlogs to disk.
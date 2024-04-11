# Liquid Functionary Source Code

This is the Rust source code of the Blocksigner and Watchman processes used by the Functionaries to run the [Liquid Network](https://liquid.net).

It includes the following crates:

- __`blocksigner`__: entrypoint to the blocksigner binary
- __`functionary`__: core libraries for blocksigner, hsm, network, and watchman
- __`functionary_common`__: common libraries used across other crates
- __`functionary_logs`__: structured logging utilities
- __`hsm_update_tool`__: a cli tool for updating hsm software
- __`init_hsm`__: a cli tool for initializing an hsm
- __`parallel_port`__: a multiplexer for multiple comms streams via a serial port
- __`watchman`__: entrypoint to the watchman binary

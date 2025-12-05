# ALNP C Binding

Contents:
- `alnp.h`: public header for control/streaming integration.
- `libalnp.a`: produced by `scripts/build_c.sh` (Rust staticlib target).

Build:
```sh
./scripts/build_c.sh
```

Link `libalnp.a` into your firmware/application and include `alnp.h` for the minimal C API.

# rz-pipe
The `rz-pipe` provides access to `rz_core_cmd_str()`.


## Usage
This function **takes a string parameter describing the rizin command** to execute and **returns a string** with the result.

```json
"fij"
```
-> 
```json
[{"name":"entry0","size":1,"offset":27296},{"name":"entry.fini0","size":1,"offset":27456},{"name":"entry.init0","size":1,"offset":27520}]
```


## Design Choice
After benchmarking various `libffi` implementations, it was found that using the native API is both more complex and slower compared to utilizing raw command strings and parsing their output.
Parsing the output can be challenging, so it's advisable to use JSON output and deserialize it into native language objects.
This approach proves to be much more convenient than dealing with and maintaining internal data structures and pointers.

Moreover, memory management becomes simpler since you only need to focus on freeing the resulting string.

## Backends
In this directory, you'll find different implementations of the `rz-pipe` API for various languages, each capable of handling different communication backends:

- Retrieving RZPIPE{_IN|_OUT} environment variables
- Spawning `rizin -q0` and communicating with pipe(2)
- Plain TCP connection
- HTTP queries (connecting to a remote webserver)
- RAP protocol (rizin's custom remote protocol)

## Supported Languages
- Python
- Go
- Haskell
- OCaml
- Rust
- Ruby

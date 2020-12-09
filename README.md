rz-pipe
======

The rz-pipe APIs are based on a single rizin primitive found behind `rz_core_cmd_str()`
which is a function that accepts a string parameter describing the rizin command to
run and returns a string with the result.

The decision behind this design comes from a series of benchmarks with different
libffi implementations and resulted that using the native API is more complex and
slower than just using raw command strings and parsing the output.

As long as the output can be tricky to parse, it's recommended to use the JSON
output and deserializing them into native language objects which results much more
handy than handling and maintaining internal data structures and pointers.

Also, memory management results into a much simpler thing because you only have
to care about freeing the resulting string.

This directory contains different implementations of the rz-pipe API for different
languages which could handle different communication backends:

  * Grab RZPIPE{_IN|_OUT} environment variables
  * Spawn `rizin -q0` and communicate with pipe(2)
  * Plain TCP connection
  * HTTP queries (connecting to a remote webserver)
  * RAP protocol (rizin own's remote protocol)

The current supported languages are:

  * Python
  * Go
  * Haskell
  * OCaml

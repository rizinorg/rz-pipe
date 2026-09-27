# rz-pipe for (Typed) Racket

This rz-pipe implementation can be used both in Typed Racket with static
type checking, and in untyped Racket with contracts evaluated at runtime.

## Installation

In this directory, to install the package user-wide:

```
raco pkg install
```

### Usage example

```racket
#lang racket

(require (prefix-in rz: rz-pipe))

(define rz (rz:open "/bin/ls"))
(printf "~v\n" (rz:cmd rz "ao @ main"))          ; string result
(printf "~v\n" (rz:cmdj rz "aoj @ main"))        ; json result
(rz:close rz)
```

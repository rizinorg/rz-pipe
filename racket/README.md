# rz-pipe for (Typed) Racket

This rz-pipe implementation can be used both in Typed Racket with static
type checking, and in untyped Racket with contracts evaluated at runtime.

## Installation

In this directory, to install the package user-wide:

```
raco pkg install
```

### Usage examples

Scripting:

```racket
#lang racket

(require (prefix-in rz: rz-pipe))

(define rz (rz:open "/bin/ls"))
(printf "~v\n" (rz:cmd rz "ao @ main"))          ; string result
(printf "~v\n" (rz:cmdj rz "aoj @ main"))        ; json result
(rz:close rz)
```

Inside a live rizin session:

```
$ rizin crackme0x00b
[0x080483e0]> #!pipe racket
Welcome to Racket v9.3 [cs].
> (require rz-pipe)
> (cmdj (open) "pdj 1")
'(#hasheq((bytes . "31ed")
          (comment . "WzEyXSAtci14IHNlY3Rpb24gc2l6ZSA0NjAgbmFtZWQgLnRleHQ=")
          (disasm . "xor ebp, ebp")
          (esil . "ebp,ebp,^=,$z,zf,:=,$p,pf,:=,31,$s,sf,:=,0,cf,:=,0,of,:=")
          (family . "cpu")
          (fcn_addr . 0)
          (fcn_last . 0)
          (flags . ("entry0" "section..text" "sym..text" "sym._start"))
          (offset . 134513632)
          (opcode . "xor ebp, ebp")
          (refptr . #f)
          (reloc . #f)
          (size . 2)
          (type . "xor")
          (type2_num . 0)
          (type_num . 28)))
>
```

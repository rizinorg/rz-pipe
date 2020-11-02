OCaml interface to rizin
-------------------------------

This is an OCaml interface to [rizin](https://github.com/rizinorg/rizin),
the reverse engineer's dream tool.

## Installation

You can install it using `opam` the OCaml package manager,
see [here](http://hyegar.com/2015/10/20/so-youre-learning-ocaml/) for
a quick introduction to the OCaml ecosystem and how to get opam.

```
$ opam install rz-pipe -y
```

## Example usage:

Here's a utop session, (`opam install utop`)

```ocaml
#require "rz-pipe";;
let result = Rz.with_command_j ~cmd:"/j chown" "/bin/ls";;
val result : Yojson.t =
`List
  [`Assoc
    [("offset", `Int 4294987375); ("id:", `Int 0);
     ("data", `String "ywritesecuritychownfile_inheritdi")]]"

Rz.with_command ~cmd:"S=" "/bin/ls" |> print_endline;;
00* 0x100000e94 |###############-----| 0x10000442d mr-x 0.__text 13.4K
01  0x10000442e |--------------##----| 0x1000045f6 mr-x 1.__stubs 0456
02  0x1000045f8 |---------------##---| 0x100004900 mr-x 2.__stub_helper  0776
03  0x100004900 |----------------#---| 0x100004af0 mr-x 3.__const  0496
04  0x100004af0 |----------------###-| 0x100004f69 mr-x 4.__cstring  1.1K
05  0x100004f6c |------------------#-| 0x100005000 mr-x 5.__unwind_info  0148
06  0x100005000 |------------------#-| 0x100005028 mrw- 6.__got  0040
07  0x100005028 |------------------#-| 0x100005038 mrw- 7.__nl_symbol_ptr  0016
08  0x100005038 |------------------#-| 0x100005298 mrw- 8.__la_symbol_ptr  0608
09  0x1000052a0 |------------------##| 0x1000054c8 mrw- 9.__const  0552
10  0x1000054d0 |-------------------#| 0x1000054f8 mrw- 10.__data  0040
11  0x100005500 |-------------------#| 0x1000055c0 mrw- 11.__bss  0192
12  0x1000055c0 |-------------------#| 0x10000564c mrw- 12.__common  0140
=>  0x100001174 |-^------------------| 0x100001274
```

## Documentation

Here is the `mli` with comments, fairly simple and high level.

```ocaml
(** A running instance of rz *)
type rz

(** Send a command to rz, get back plain string output *)
val command : rz:rz -> string -> string

(** Send a command to rz, get back Yojson. If output isn't JSON
    parsable then raises {Invalid_argument} so make sure command ends
    with 'j' *)
val command_json : rz:rz -> string -> Yojson.t

(** Create a rz instance with a given file, raises {Invalid_argument}
    if file doesn't exists *)
val open_file : string -> rz

(** close a rz instance *)
val close : rz -> unit

(** Convenience function for opening a rz instance, sending a command,
    getting the result as plain string and closing the rz instance *)
val with_command : cmd:string -> string -> string

(** Convenience function for opening a rz instance, sending a command,
    getting the result as Yojson and closing the rz instance *)
val with_command_j : cmd:string -> string -> Yojson.t
```

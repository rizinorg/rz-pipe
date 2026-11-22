#lang scribble/manual

@(require (for-label typed/racket/base
                     racket/port
                     json
                     rz-pipe))

@title{rz-pipe}
@author[(author+email "RizinOrg" "core@rizin.re")]
@defmodule[rz-pipe]

This package provides a scripting interface for the
@hyperlink["https://rizin.re/"]{Rizin Reverse Engineering Framework} that
builds upon Rizin's command interface as a simple point of interaction.

While this library itself is written in Typed Racket, it can also be used in
untyped Racket with contracts evaluated at runtime.

@section{Examples}

Scripting:

@codeblock|{
#lang racket

(require (prefix-in rz: rz-pipe))

(define rz (rz:open "/bin/ls"))
(printf "~v\n" (rz:cmd rz "ao @ main"))          ; string result
(printf "~v\n" (rz:cmdj rz "aoj @ main"))        ; json result
(rz:close rz)
}|

Inside a live Rizin session:

@verbatim[#:indent 2]|{
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
}|

@section{Reference}

@defidform[#:kind "type" Rizin]{
Represents a connection to a running Rizin session.
}

@defproc[(rizin? [v Any]) Boolean]{
Returns @racket[#t] if @racket[v] is a @racket[Rizin], @racket[#f] otherwise.
}

@defproc[(open [filename (U Bytes Path-String #f) #f]
               [#:stderr err-mode (U 'forward 'ignore) 'forward])
         Rizin]{
Opens a connection to Rizin.

If @racket[filename] is given, a new Rizin instance is started as a subprocess
and attached to. Pass @racket["--"] as @racket[filename] if no file should be opened.
In this mode, @racket[err-mode] defines how to handle the subprocess's stderr
output:

@itemlist[
  @item{@racket['ignore] hides stderr.}
  @item{@racket['forward] @racket[copy-port]s it into
        @racket[(current-error-port)].}
]

If @racket[filename] is @racket[#f], @racket[open] tries to attach to an
existing Rizin session hosting the current Racket process. This is meant to be
used when running under the @tt{#!pipe} command inside Rizin itself.

Raises:

@itemlist[
  @item{@racket[exn:fail:rz-pipe:rizin-not-found]}
  @item{@racket[exn:fail:rz-pipe:startup]}
  @item{@racket[exn:fail:rz-pipe:unexpected-data]}
]
}

@defproc[(close [rz Rizin]) Void]{
Closes the given connection to Rizin.
}

@defproc[(cmd [rz Rizin] [command String]) String]{
Executes @racket[command] inside Rizin and returns its output verbatim as a
string.

Raises @racket[exn:fail:rz-pipe:unexpected-data] if Rizin closed its output
before the result of @racket[command] was fully received, for example because
the Rizin process has exited.
}

@defproc[(cmdj [rz Rizin] [command String]) JSExpr]{
Same as @racket[cmd], but the output is parsed as JSON and returned as a
@racket[jsexpr?] value. Make sure that
@racket[command] is a command that outputs JSON, usually one with the
@litchar{j} suffix.

Raises @racket[exn:fail:read] if the output of @racket[command] is not valid
JSON.
}

@defstruct*[(exn:fail:rz-pipe:rizin-not-found exn:fail) ()]{
The @exec{rizin} executable could not be found in @envvar{PATH}, or
@envvar{RZ_PIPE_IN}/@envvar{RZ_PIPE_OUT} are not available when attaching to an
existing session.
}

@defstruct*[(exn:fail:rz-pipe:startup exn:fail) ()]{
Rizin failed to start, either because the given file could not be opened or
because another error occurred.
}

@defstruct*[(exn:fail:rz-pipe:unexpected-data exn:fail) ()]{
Rizin sent data the library did not recognize.
}

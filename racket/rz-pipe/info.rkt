#lang info
(define collection "rz-pipe")
(define pkg-desc "Scripting interface for the Rizin Reverse Engineering Framework (implementation and documentation)")
(define license '(LGPL-3.0-only OR MIT))
(define deps '("base" "rz-pipe-lib"))
(define implies '("rz-pipe-lib"))
(define build-deps '("scribble-lib" "typed-racket-lib" "racket-doc" "typed-racket-doc"))
(define scribblings '(("scribblings/rz-pipe.scrbl")))

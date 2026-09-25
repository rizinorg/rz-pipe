#lang typed/racket/base

(require racket/string
         racket/port
         typed/json)

(provide
  Rizin
  rizin?
  open
  close
  cmd
  cmdj
  (struct-out exn:fail:rz-pipe:rizin-not-found)
  (struct-out exn:fail:rz-pipe:unexpected-data))

(struct rizin
  ([sp : Subprocess]
   [out : Input-Port]
   [in : Output-Port])
  #:type-name Rizin)

(struct exn:fail:rz-pipe:rizin-not-found exn:fail ())
(struct exn:fail:rz-pipe:unexpected-data exn:fail ())

(define (open [filename : (U Bytes Path-String)] #:stderr [err-mode : (U 'forward 'ignore) 'forward]) : Rizin
  (define rizin-path (find-executable-path "rizin"))
  (unless rizin-path
    (raise (exn:fail:rz-pipe:rizin-not-found "open: rizin executable was not found in PATH" (current-continuation-marks))))
  (define-values (sp out in err)
    (subprocess #f #f #f rizin-path #"-q0" filename))
  (define err-dst
    ; we could pass (current-error-port) to subprocess above, but this will not work if
    ; that is not a file-stream-port?, as is the case in DrRacket for example.
    (case err-mode
      [(forward) (current-error-port)]
      [(ignore) (open-output-nowhere)]))
  (thread
    (λ ()
      (copy-port err err-dst)
      (close-input-port err)))
  (unless (equal? (read-byte out) 0) ; read initial \0
    (raise (exn:fail:rz-pipe:unexpected-data "open: rizin did not write initial 0-byte" (current-continuation-marks))))
  (rizin sp out in))

(define (close [rz : Rizin])
  (cmd rz "q")
  (close-input-port (rizin-out rz))
  (close-output-port (rizin-in rz))
  (subprocess-wait (rizin-sp rz)))

(define (cmd [rz : Rizin] [command : String]) : String
  (define normalized (string-replace command "\n" ";"))
  (write-string normalized (rizin-in rz))
  (newline (rizin-in rz))
  (flush-output (rizin-in rz))
  (define m (regexp-match #rx#"^([^\0]*)\0" (rizin-out rz)))
  (unless m (raise (exn:fail:rz-pipe:unexpected-data "cmd: rizin stdout was closed" (current-continuation-marks))))
  (bytes->string/utf-8 (assert (cadr m) bytes?)))

(define (cmdj [rz : Rizin] [command : String]) : JSExpr (string->jsexpr (cmd rz command)))

(module+ test
  (require typed/rackunit)
  (define rz (open "malloc://1024"))
  (void (cmd rz "w \"Hello World\""))
  (check-equal? (cmd rz "ps") "Hello World\n")
  (define j (cmdj rz "psj"))
  (check-equal? (hash-ref (assert j hash?) 'string) "Hello World")
  (close rz))

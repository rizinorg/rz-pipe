#lang typed/racket/base

(require racket/string
         racket/port
         typed/json)

(require/typed
  ffi/unsafe/port
  [[unsafe-file-descriptor->port unsafe-fd->input-port] (-> Integer Any (List 'read) Input-Port)]
  [[unsafe-file-descriptor->port unsafe-fd->output-port] (-> Integer Any (List 'write) Output-Port)])

(provide
  Rizin
  rizin?
  open
  close
  cmd
  cmdj
  (struct-out exn:fail:rz-pipe:rizin-not-found)
  (struct-out exn:fail:rz-pipe:startup)
  (struct-out exn:fail:rz-pipe:unexpected-data))

(struct rizin
  ([out : Input-Port]
   [in : Output-Port]
   [close : (-> Rizin Void)])
  #:type-name Rizin)

(struct exn:fail:rz-pipe:rizin-not-found exn:fail ())
(struct exn:fail:rz-pipe:startup exn:fail ())
(struct exn:fail:rz-pipe:unexpected-data exn:fail ())

(define (open-piped) : Rizin
  (define (env-num [k : String]) : (U Exact-Nonnegative-Integer #f)
    (define v (getenv k))
    (define num (and v (string->number v)))
    (and (exact-nonnegative-integer? num) num))
  (define in-fd (env-num "RZ_PIPE_IN"))
  (define out-fd (env-num "RZ_PIPE_OUT"))
  (unless (and in-fd out-fd)
    (raise (exn:fail:rz-pipe:rizin-not-found "open: RZ_PIPE_IN/RZ_PIPE_OUT vars not available or invalid" (current-continuation-marks))))
  (rizin
    (unsafe-fd->input-port in-fd 'rz-pipe-in '(read))
    (unsafe-fd->output-port out-fd 'rz-pipe-out '(write))
    (λ (_) (void))))

(define (open-filename [filename : (U Bytes Path-String)] #:stderr [err-mode : (U 'forward 'ignore) 'forward]) : Rizin
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
  (let ([init-byte (read-byte out)]) ; read initial \0
       (unless (equal? init-byte 0)
         (if (eof-object? init-byte)
             (raise (exn:fail:rz-pipe:startup
                      "open: rizin failed to start or the given file could not be opened"
                      (current-continuation-marks)))
             (raise (exn:fail:rz-pipe:unexpected-data
                      (format "open: rizin did not write initial 0-byte, but instead ~v" init-byte)
                      (current-continuation-marks))))))
  (rizin out in
         (λ (rz)
            (cmd rz "q")
            (close-input-port (rizin-out rz))
            (close-output-port (rizin-in rz))
            (subprocess-wait sp))))

(define (open [filename : (U Bytes Path-String #f) #f] #:stderr [err-mode : (U 'forward 'ignore) 'forward]) : Rizin
  (if filename
      (open-filename filename #:stderr err-mode)
      (open-piped)))

(define (close [rz : Rizin]) ((rizin-close rz) rz))

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
  (require typed/rackunit
           typed/racket/system)
  (let ([rz (open "malloc://1024")])
    (void (cmd rz "w \"Hello World\""))
    (test-equal? "cmd" (cmd rz "ps") "Hello World\n")
    (define j (cmdj rz "psj"))
    (test-equal? "cmdj" (hash-ref (assert j hash?) 'string) "Hello World")
    (close rz))
  (test-exn "non-existent file" exn:fail:rz-pipe:startup?
    (λ () (open "/this/file/does/not/exist" #:stderr 'ignore)))
  (test-equal?
    "embedded rz-pipe"
    (with-output-to-string (λ ()
      (system*
        (assert (find-executable-path "rizin"))
        "-qc"
        "#!pipe racket -e \\'(require \"./main.rkt\") (cmdj (open) \"pxj 1\")\\'"
        "hex://2a")))
    "'(42)\n"))

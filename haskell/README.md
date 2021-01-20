# rz-pipe for Haskell

rz-pipe is a scripting interface for the Rizin Reverse Engineering
Framework that builds upon Rizin's command interface as a simple
point of interaction.

It can be used by launching a Rizin instance from Haskell or
connecting to an existing one using pipes or HTTP.

## Usage

The API revolves around the `RzContext` type, which represents
a connection to a running Rizin instance. The `open` function
will establish such a connection in `IO` based on its argument:

```haskell
do
  -- Spawn a new rizin instance and open the /bin/ls binary in it
  localCtx <- open $ Just "/bin/ls"
  -- Pick up pipes from parent rizin process
  parentCtx <- open Nothing
  -- Connect to rizin via HTTP (e.g. if "rizin -qc=h /bin/ls" is running)
  httpCtx <- open $ Just "http://127.0.0.1:9090"
```

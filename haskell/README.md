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

Once a context has been opened, the `cmd` function can be used
to run commands and return the result as a string in `IO`:

```haskell
putStrLn =<< cmd ctx "pd 3"
-- prints e.g.
--   0x00005b20      endbr64
--   0x00005b24      xor   ebp, ebp
--   0x00005b26      mov   r9, rdx
```

For scripting, it is highly recommended to use rizin commands returning
json, commonly prefixed with `j`. To conveniently parse the results with
[aeson](https://hackage.haskell.org/package/aeson), the `cmdj` can be
used, which is polymorphic in its return type and can produce any object
in the `Data.Aeson.FromJSON` type class:

```haskell
{-# LANGUAGE DeriveGeneric, DeriveAnyClass #-}

import RzPipe
import GHC.Generics
import Data.Aeson as JSON
import Data.Word

data Flag = Flag
    { name :: String
    , size :: Word64
    , offset :: Word64 }
    deriving (Show, Generic, JSON.FromJSON)

showFlags :: RzContext -> IO ()
showFlags ctx = print =<< (cmdj ctx "fj" :: IO (Maybe [Flag]))
-- prints e.g.
-- Just [Flag {name = "section.", size = 0, offset = 0},Flag {name = "section..comment", size = 76, offset = 0},Flag {name = "section..shstrtab", size = 247, offset = 0},Flag {name = "segment.LOAD0", size = 13584, offset = 0},Flag {name = "segment.GNU_STACK", size = 0, offset = 0},Flag {name = "segment.ehdr", size = 64, offset = 0} ...
```


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

showMainFunction :: RzContext -> IO ()
showMainFunction ctx = do
    cmd ctx "s main"
    putStrLn =<< cmd ctx "pD `fl $$`"

showFlags :: RzContext -> IO ()
showFlags ctx = print =<< (cmdj ctx "fj" :: IO (Maybe [Flag]))

main :: IO ()
main = do
    -- Spawn a new rizin instance and open the /bin/ls binary in it
    ctx <- open $ Just "/bin/ls"
    -- Pick up pipes from parent rizin process
    -- ctx <- open Nothing
    -- Connect to rizin via HTTP (e.g. if "rizin -qc=h /bin/ls" is running)
    -- ctx <- open $ Just "http://127.0.0.1:9090"
    showMainFunction ctx
    showFlags ctx

import RzPipe
import qualified Data.ByteString.Lazy as L

showMainFunction ctx = do
    cmd ctx "s main"
    L.putStr =<< cmd ctx "pD `fl $$`"

main = do
    -- Run rizin locally
    open (Just "/bin/ls") >>= showMainFunction
    -- Pick up pipes from parent rizin process
    open Nothing >>= showMainFunction
    -- Connect to rizin via HTTP (e.g. if "r2 -qc=h /bin/ls" is running)
    open (Just "http://127.0.0.1:9090") >>= showMainFunction

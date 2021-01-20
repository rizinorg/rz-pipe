import RzPipe

showMainFunction ctx = do
    cmd ctx "s main"
    putStrLn =<< cmd ctx "pD `fl $$`"

main = do
    -- Spawn a new rizin instance and open the /bin/ls binary in it
    open (Just "/bin/ls") >>= showMainFunction
    -- Pick up pipes from parent rizin process
    open Nothing >>= showMainFunction
    -- Connect to rizin via HTTP (e.g. if "rizin -qc=h /bin/ls" is running)
    open (Just "http://127.0.0.1:9090") >>= showMainFunction

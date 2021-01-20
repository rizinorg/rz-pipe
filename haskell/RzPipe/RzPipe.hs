module RzPipe (RzContext(), open, cmd, cmdj) where
import Data.Char
import Data.Word
import Network.HTTP
import System.IO
import System.Process
import System.Environment (getEnv)
import GHC.IO.Handle.FD
import System.Posix.Internals (FD)
import qualified Data.Aeson as JSON
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.UTF8 as U

withPipes p = p { std_in = CreatePipe, std_out = CreatePipe, std_err = CreatePipe }

createProcess' args = fmap f $ createProcess (withPipes args) where
    f (Just i, Just o, Just e, h) = (i, o, e, h)
    f _ = error "createProcess': Failed to open pipes to the subprocess."

lHTakeWhile :: (Word8 -> Bool) -> Handle -> IO B.ByteString
lHTakeWhile p h = do
    c <- fmap B.head $ B.hGet h 1
    if p c
        then fmap (c `B.cons`) $ lHTakeWhile p h
        else return B.empty

data RzContext = HttpCtx String
               | PipeCtx Handle Handle

open :: Maybe String -> IO RzContext
open (Just url@('h':'t':'t':'p':_)) = return $ HttpCtx (url ++ "/cmd/")
open (Just filename) = do
    (hIn, hOut, _, _) <- createProcess' $ proc "rizin" ["-q0", filename]
    lHTakeWhile (/= 0) hOut -- drop the inital null that rizin emits
    return $ PipeCtx hIn hOut
open Nothing = do
    hIn <- fdToHandle =<< (read::(String -> FD)) <$> getEnv "RZ_PIPE_OUT"
    hOut <- fdToHandle =<< (read::(String -> FD)) <$> getEnv "RZ_PIPE_IN"
    return $ PipeCtx hIn hOut

cmdHttp :: String -> String -> IO String
cmdHttp url cmd = getResponseBody =<< simpleHTTP (getRequest (url ++ urlEncode cmd))

cmdPipe :: Handle -> Handle -> String -> IO B.ByteString
cmdPipe hIn hOut cmd = hPutStrLn hIn cmd >> hFlush hIn >> lHTakeWhile (/= 0) hOut

cmdB :: RzContext -> String -> IO B.ByteString
cmdB (HttpCtx url) cmd = U.fromString <$> cmdHttp url cmd
cmdB (PipeCtx hIn hOut) cmd = cmdPipe hIn hOut cmd

cmd :: RzContext -> String -> IO String
cmd (HttpCtx url) cmd = cmdHttp url cmd
cmd (PipeCtx hIn hOut) cmd = U.toString <$> cmdPipe hIn hOut cmd

cmdj :: JSON.FromJSON a => RzContext -> String -> IO (Maybe a)
cmdj = (fmap JSON.decode .) . cmdB

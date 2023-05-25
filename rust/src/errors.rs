use std::io;

use reqwest;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RzInitError {
    #[error("No rizin session open. Please specify path")]
    NoSessionOpenError,

    #[error("Path could not be resolved or we do not have an open session")]
    PathNotResolvableError,

    #[error("root cause of the error is unknown")]
    Other,
}

#[derive(Error, Debug)]
pub enum RzPipeError {
    #[error("Pipe not open. Please run from rizin")]
    NotOpen,

    #[error("Flushing out the null byte failed")]
    FlushInitialNullByte(#[from] io::Error),

    #[error("Called cmd on RzPipe::None. You probably want to use open for a proper pipe")]
    CmdIsNoop,

    #[error("Called cmdj on RzPipe::None. You probably want to use open for a proper pipe")]
    CmdjIsNoop,

    #[error("Called close on RzPipe::None. You probably want to use open for a proper pipe")]
    CloseIsNoop,

    #[error("Unable to get peer address")]
    PeerAddressNotAvailable,

    #[error("Please provide 2 Vectors of the same size for names and options")]
    ThreadVectorValue,

    #[error("The concrete pipe implementation has an underlying issue: `{0}`")]
    ConcretePipe(String),

    #[error("root cause of the error is unknown: {0}")]
    Other(String),
}

impl From<&str> for RzPipeError {
    #[inline]
    fn from(s: &str) -> RzPipeError {
        RzPipeError::Other(s.to_owned())
    }
}

#[derive(Error, Debug)]
pub enum RzPipeThreadError {
    #[error("Channel send error`{0}`")]
    ChannelSend(String),

    #[error("Channel recv error: `{0}`")]
    ChannelRecv(String),

    #[error("Channel try_recv error: `{0}`")]
    ChannelTryRecv(String),

    #[error("root cause of the error is unknown")]
    Other,
}

#[derive(Error, Debug)]
pub enum RzPipeSpawnError {
    #[error("json of cmdj invocation is empty")]
    EmptyJson,

    #[error("json of cmdj invocation could not be parsed: `{0}`")]
    ParsingJson(String),

    #[error("Writing a cmd to pipe failed: `{0}`")]
    WriteCmd(String),

    #[error("Reading response of cmd from pipe failed: `{0}`")]
    ReadCmdResponse(String),

    #[error("Processing of cmd result failed: `{0}`")]
    ProcessResult(String),

    #[error("root cause of the error is unknown")]
    Other,
}

#[derive(Error, Debug)]
pub enum RzPipeLangError {
    #[error("Could not read until buffered reader until the end: {0}")]
    BufferNotFullyReadable(String),

    #[error("json of cmdj invocation could not be parsed: `{0}`")]
    ParsingJson(String),

    #[error("Processing of cmd result failed: `{0}`")]
    ProcessResult(String),

    #[error("root cause of the error is unknown")]
    Other,
}

#[derive(Error, Debug)]
pub enum RzPipeHttpError {
    #[error("utf-8 decode error: `{0}`")]
    DecodeError(String),

    #[error("json of cmdj invocation could not be parsed: `{0}`")]
    ParsingJson(String),

    #[error("http error")]
    RequestError(#[from] reqwest::Error),

    #[error("root cause of the error is unknown")]
    Other,
}

#[derive(Error, Debug)]
pub enum RzPipeTcpError {
    #[error("json of cmdj invocation could not be parsed: `{0}`")]
    ParsingJson(String),

    #[error("Unable to connect TCP stream: `{0}`")]
    Connection(String),

    #[error("Unable to write to TCP stream: `{0}`")]
    Write(String),

    #[error("Unable to read from TCP stream: `{0}`")]
    Read(String),

    #[error("Processing of cmd result failed: `{0}`")]
    ProcessResult(String),

    #[error("root cause of the error is unknown")]
    Other,
}

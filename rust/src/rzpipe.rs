//! Provides functionality to connect with rizin.
//!
//! Please check crate level documentation for more details and examples.

use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process;
use std::process::Command;
use std::process::Stdio;
use std::str;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use libc;
use reqwest;
use serde_json::Value;

use crate::errors::RzPipeLangError;
use crate::{RzPipeError, RzPipeHttpError, RzPipeSpawnError, RzPipeTcpError, RzPipeThreadError};

/// File descriptors to the parent rizin process.
pub struct RzPipeLang {
    read: BufReader<File>,
    write: File,
}

/// Stores descriptors to the spawned rizin process.
pub struct RzPipeSpawn {
    read: BufReader<process::ChildStdout>,
    write: process::ChildStdin,
}

/// Stores the socket address of the rizin process.
pub struct RzPipeTcp {
    socket_addr: SocketAddr,
}

pub struct RzPipeHttp {
    host: String,
}

/// Stores thread metadata
/// It stores both a sending and receiving end to the thread, allowing
/// convenient interaction. So we can send commands using
/// RzPipeThread::send() and fetch outputs using RzPipeThread::recv()
pub struct RzPipeThread {
    rzrecv: mpsc::Receiver<String>,
    rzsend: mpsc::Sender<String>,
    pub id: u16,
    pub handle: thread::JoinHandle<()>,
}

#[derive(Default, Clone)]
pub struct RzPipeSpawnOptions {
    pub exepath: String,
    pub args: Vec<&'static str>,
}

/// Provides abstraction between the three invocation methods.
pub enum RzPipe {
    Pipe(RzPipeSpawn),
    Lang(RzPipeLang),
    Tcp(RzPipeTcp),
    Http(RzPipeHttp),
    None,
}

fn atoi(k: &str) -> i32 {
    k.parse::<i32>().unwrap_or(-1)
}

fn getenv(k: &str) -> i32 {
    match env::var(k) {
        Ok(val) => atoi(&val),
        Err(_) => -1,
    }
}

fn process_result(res: Vec<u8>) -> Result<String, String> {
    let len = res.len();
    if len == 0 {
        return Err("Failed".to_string());
    }
    let result = str::from_utf8(&res[..len - 1])
        .map_err(|e| e.to_string())?
        .to_string();
    Ok(result)
}

#[macro_export]
macro_rules! open_pipe {
    () => {
        RzPipe::open(),
    };
    ($x: expr) => {
        match $x {
            Some(path) => RzPipe::spawn(path, None),
            None => RzPipe::open(),
        }
    };
    ($x: expr, $y: expr) => {
        match $x $y {
            Some(path, opts) => RzPipe::spawn(path, opts),
            (None, None) => RzPipe::open(),
        }
    }
}

impl RzPipe {
    #[cfg(not(windows))]
    pub fn open() -> Result<RzPipe, RzPipeError> {
        use std::os::unix::io::FromRawFd;

        let (f_in, f_out) = match RzPipe::in_session() {
            Some(x) => x,
            None => return Err(RzPipeError::NotOpen),
        };
        let res = unsafe {
            // dup file descriptors to avoid from_raw_fd ownership issue
            let (d_in, d_out) = (libc::dup(f_in), libc::dup(f_out));
            RzPipeLang {
                read: BufReader::new(File::from_raw_fd(d_in)),
                write: File::from_raw_fd(d_out),
            }
        };
        Ok(RzPipe::Lang(res))
    }

    #[cfg(windows)]
    pub fn open() -> Result<RzPipe, RzPipeError> {
        Err(RzPipeError::Other(
            "`open()` is not yet supported on Windows".to_string(),
        ))
    }

    pub fn cmd(&mut self, cmd: &str) -> Result<String, RzPipeError> {
        match *self {
            RzPipe::Pipe(ref mut x) => x
                .cmd(cmd.trim())
                .map_err(|e| RzPipeError::ConcretePipe(e.to_string())),
            RzPipe::Lang(ref mut x) => x
                .cmd(cmd.trim())
                .map_err(|e| RzPipeError::ConcretePipe(e.to_string())),
            RzPipe::Tcp(ref mut x) => x
                .cmd(cmd.trim())
                .map_err(|e| RzPipeError::ConcretePipe(e.to_string())),
            RzPipe::Http(ref mut x) => x
                .cmd(cmd.trim())
                .map_err(|e| RzPipeError::ConcretePipe(e.to_string())),
            RzPipe::None => Err(RzPipeError::CmdIsNoop),
        }
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value, RzPipeError> {
        match *self {
            RzPipe::Pipe(ref mut x) => x
                .cmdj(cmd.trim())
                .map_err(|e| RzPipeError::ConcretePipe(e.to_string())),
            RzPipe::Lang(ref mut x) => x
                .cmdj(cmd.trim())
                .map_err(|e| RzPipeError::ConcretePipe(e.to_string())),
            RzPipe::Tcp(ref mut x) => x
                .cmdj(cmd.trim())
                .map_err(|e| RzPipeError::ConcretePipe(e.to_string())),
            RzPipe::Http(ref mut x) => x
                .cmdj(cmd.trim())
                .map_err(|e| RzPipeError::ConcretePipe(e.to_string())),
            RzPipe::None => Err(RzPipeError::CmdjIsNoop),
        }
    }

    pub fn close(&mut self) {
        match *self {
            RzPipe::Pipe(ref mut x) => x.close(),
            RzPipe::Lang(ref mut x) => x.close(),
            RzPipe::Tcp(ref mut x) => x.close(),
            RzPipe::Http(ref mut x) => x.close(),
            RzPipe::None => {
                eprintln!("{:?}", RzPipeError::CloseIsNoop)
            }
        }
    }

    pub fn in_session() -> Option<(i32, i32)> {
        let f_in = getenv("RZPIPE_IN");
        let f_out = getenv("RZPIPE_OUT");
        if f_in < 0 || f_out < 0 {
            return None;
        }
        Some((f_in, f_out))
    }

    #[cfg(windows)]
    pub fn in_windows_session() -> Option<String> {
        match env::var("RZPIPE_PATH") {
            Ok(val) => Some(format!("\\\\.\\pipe\\{}", val)),
            Err(_) => None,
        }
    }

    /// Creates a new RzPipeSpawn.
    pub fn spawn<T: AsRef<str>>(
        name: T,
        opts: Option<RzPipeSpawnOptions>,
    ) -> Result<RzPipe, RzPipeError> {
        if name.as_ref() == "" && RzPipe::in_session().is_some() {
            return RzPipe::open();
        }

        let exepath = match opts {
            Some(ref opt) => opt.exepath.clone(),
            _ => "rizin".to_owned(),
        };
        let args = match opts {
            Some(ref opt) => opt.args.clone(),
            _ => vec![],
        };
        let path = Path::new(name.as_ref());
        let child = Command::new(exepath)
            .arg("-q0")
            .args(&args)
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| "Unable to spawn Rizin.")?;

        let sin = child.stdin.unwrap();
        let mut sout = child.stdout.unwrap();

        // flush out the initial null byte.
        let mut w = [0; 1];
        sout.read_exact(&mut w)
            .map_err(RzPipeError::FlushInitialNullByte)?;

        let res = RzPipeSpawn {
            read: BufReader::new(sout),
            write: sin,
        };

        Ok(RzPipe::Pipe(res))
    }

    /// Creates a new RzPipeTcp
    pub fn tcp<A: ToSocketAddrs>(addr: A) -> Result<RzPipe, RzPipeError> {
        // use `connect` to figure out which socket address works
        let stream = TcpStream::connect(addr).map_err(|_| "Unable to connect TCP stream")?;
        let addr = stream
            .peer_addr()
            .map_err(|_| RzPipeError::PeerAddressNotAvailable)?;
        Ok(RzPipe::Tcp(RzPipeTcp { socket_addr: addr }))
    }

    /// Creates a new RzPipeHttp
    pub fn http(host: &str) -> Result<RzPipe, RzPipeError> {
        Ok(RzPipe::Http(RzPipeHttp {
            host: host.to_string(),
        }))
    }

    /// Creates new pipe threads
    /// First two arguments for RzPipe::threads() are the same as for RzPipe::spawn() but inside vectors
    /// Third and last argument is an option to a callback function
    /// The callback function takes two Arguments: Thread ID and rzpipe output
    pub fn threads(
        names: Vec<&'static str>,
        opts: Vec<Option<RzPipeSpawnOptions>>,
        callback: Option<Arc<dyn Fn(u16, String) + Sync + Send>>,
    ) -> Result<Vec<RzPipeThread>, RzPipeError> {
        if names.len() != opts.len() {
            return Err(RzPipeError::ThreadVectorValue);
        }

        let mut pipes = Vec::new();

        for n in 0..names.len() {
            let (htx, rx) = mpsc::channel();
            let (tx, hrx) = mpsc::channel();
            let name = names[n];
            let opt = opts[n].clone();
            let cb = callback.clone();
            let t = thread::spawn(move || {
                let mut rz = RzPipe::spawn(name, opt).unwrap();
                'outer: loop {
                    let cmd: String = hrx.recv().unwrap();
                    if cmd == "q" {
                        break;
                    }
                    let res = rz.cmdj(&cmd).unwrap().to_string();
                    let result = htx.send(res.clone());
                    if let Err(e) = result {
                        eprintln!("{}", e);
                        break 'outer;
                    }
                    if let Some(cbs) = cb.clone() {
                        thread::spawn(move || {
                            cbs(n as u16, res);
                        });
                    };
                }
            });
            pipes.push(RzPipeThread {
                rzrecv: rx,
                rzsend: tx,
                id: n as u16,
                handle: t,
            });
        }
        Ok(pipes)
    }
}

impl RzPipeThread {
    pub fn send(&self, cmd: String) -> Result<(), RzPipeThreadError> {
        self.rzsend
            .send(cmd)
            .map_err(|e| RzPipeThreadError::ChannelSend(e.to_string()))
    }

    pub fn recv(&self, block: bool) -> Result<String, RzPipeThreadError> {
        if block {
            return self
                .rzrecv
                .recv()
                .map_err(|e| RzPipeThreadError::ChannelRecv(e.to_string()));
        }
        self.rzrecv
            .try_recv()
            .map_err(|e| RzPipeThreadError::ChannelTryRecv(e.to_string()))
    }
}

impl RzPipeSpawn {
    pub fn cmd(&mut self, cmd: &str) -> Result<String, RzPipeSpawnError> {
        let cmd = cmd.to_owned() + "\n";
        self.write
            .write_all(cmd.as_bytes())
            .map_err(|e| RzPipeSpawnError::WriteCmd(e.to_string()))?;

        let mut res: Vec<u8> = Vec::new();
        self.read
            .read_until(0u8, &mut res)
            .map_err(|e| RzPipeSpawnError::ReadCmdResponse(e.to_string()))?;

        process_result(res).map_err(RzPipeSpawnError::ProcessResult)
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value, RzPipeSpawnError> {
        let result = self.cmd(cmd)?;
        if result.is_empty() {
            return Err(RzPipeSpawnError::EmptyJson);
        }
        serde_json::from_str(&result).map_err(|e| RzPipeSpawnError::ParsingJson(e.to_string()))
    }

    pub fn close(&mut self) {
        let _ = self.cmd("q!");
    }
}

impl RzPipeLang {
    pub fn cmd(&mut self, cmd: &str) -> Result<String, RzPipeLangError> {
        self.write.write_all(cmd.as_bytes()).unwrap();
        let mut res: Vec<u8> = Vec::new();
        let buffer = self.read.read_until(0u8, &mut res);

        match buffer {
            Ok(_) => process_result(res).map_err(RzPipeLangError::ProcessResult),
            Err(e) => Err(RzPipeLangError::BufferNotFullyReadable(e.to_string())),
        }
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value, RzPipeLangError> {
        let res = self.cmd(cmd)?;
        serde_json::from_str(&res).map_err(|e| RzPipeLangError::ParsingJson(e.to_string()))
    }

    pub fn close(&mut self) {}
}

impl RzPipeHttp {
    pub fn cmd(&mut self, cmd: &str) -> Result<String, RzPipeHttpError> {
        let url = format!("http://{}/cmd/{}", self.host, cmd);
        let res = reqwest::blocking::get(url)?;
        let bytes = res.bytes()?.to_vec();
        str::from_utf8(bytes.as_slice())
            .map(|s| s.to_string())
            .map_err(|err| RzPipeHttpError::DecodeError(err.to_string()))
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value, RzPipeHttpError> {
        let res = self.cmd(cmd)?;
        serde_json::from_str(&res).map_err(|e| RzPipeHttpError::ParsingJson(e.to_string()))
    }

    pub fn close(&mut self) {}
}

impl RzPipeTcp {
    pub fn cmd(&mut self, cmd: &str) -> Result<String, RzPipeTcpError> {
        let mut stream = TcpStream::connect(self.socket_addr)
            .map_err(|e| RzPipeTcpError::Connection(e.to_string()))?;
        stream
            .write_all(cmd.as_bytes())
            .map_err(|e| RzPipeTcpError::Write(e.to_string()))?;
        let mut res: Vec<u8> = Vec::new();
        stream
            .read_to_end(&mut res)
            .map_err(|e| RzPipeTcpError::Read(e.to_string()))?;
        res.push(0);
        process_result(res).map_err(RzPipeTcpError::ProcessResult)
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value, RzPipeTcpError> {
        let res = self.cmd(cmd)?;
        serde_json::from_str(&res).map_err(|e| RzPipeTcpError::ParsingJson(e.to_string()))
    }

    pub fn close(&mut self) {}
}

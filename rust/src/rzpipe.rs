//! Provides functionality to connect with rizin.
//!
//! Please check crate level documentation for more details and examples.

use reqwest;

use libc;
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

use serde_json;
use serde_json::Value;

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
}

fn atoi(k: &str) -> i32 {
    match k.parse::<i32>() {
        Ok(val) => val,
        Err(_) => -1,
    }
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
    pub fn open() -> Result<RzPipe, &'static str> {
        use std::os::unix::io::FromRawFd;

        let (f_in, f_out) = match RzPipe::in_session() {
            Some(x) => x,
            None => return Err("Pipe not open. Please run from rizin"),
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
    pub fn open() -> Result<RzPipe, &'static str> {
        Err("`open()` is not yet supported on windows")
    }

    pub fn cmd(&mut self, cmd: &str) -> Result<String, String> {
        match *self {
            RzPipe::Pipe(ref mut x) => x.cmd(cmd.trim()),
            RzPipe::Lang(ref mut x) => x.cmd(cmd.trim()),
            RzPipe::Tcp(ref mut x) => x.cmd(cmd.trim()),
            RzPipe::Http(ref mut x) => x.cmd(cmd.trim()),
        }
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value, String> {
        match *self {
            RzPipe::Pipe(ref mut x) => x.cmdj(cmd.trim()),
            RzPipe::Lang(ref mut x) => x.cmdj(cmd.trim()),
            RzPipe::Tcp(ref mut x) => x.cmdj(cmd.trim()),
            RzPipe::Http(ref mut x) => x.cmdj(cmd.trim()),
        }
    }

    pub fn close(&mut self) {
        match *self {
            RzPipe::Pipe(ref mut x) => x.close(),
            RzPipe::Lang(ref mut x) => x.close(),
            RzPipe::Tcp(ref mut x) => x.close(),
            RzPipe::Http(ref mut x) => x.close(),
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
    ) -> Result<RzPipe, &'static str> {
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
        sout.read_exact(&mut w).unwrap();

        let res = RzPipeSpawn {
            read: BufReader::new(sout),
            write: sin,
        };

        Ok(RzPipe::Pipe(res))
    }

    /// Creates a new RzPipeTcp
    pub fn tcp<A: ToSocketAddrs>(addr: A) -> Result<RzPipe, &'static str> {
        // use `connect` to figure out which socket address works
        let stream = TcpStream::connect(addr).map_err(|_| "Unable to connect TCP stream")?;
        let addr = stream
            .peer_addr()
            .map_err(|_| "Unable to get peer address")?;
        Ok(RzPipe::Tcp(RzPipeTcp { socket_addr: addr }))
    }

    /// Creates a new RzPipeHttp
    pub fn http(host: &str) -> Result<RzPipe, &'static str> {
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
    ) -> Result<Vec<RzPipeThread>, &'static str> {
        if names.len() != opts.len() {
            return Err("Please provide 2 Vectors of the same size for names and options");
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
                loop {
                    let cmd: String = hrx.recv().unwrap();
                    if cmd == "q" {
                        break;
                    }
                    let res = rz.cmdj(&cmd).unwrap().to_string();
                    htx.send(res.clone()).unwrap();
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
    pub fn send(&self, cmd: String) -> Result<(), &'static str> {
        self.rzsend.send(cmd).map_err(|_| "Channel send error")
    }

    pub fn recv(&self, block: bool) -> Result<String, &'static str> {
        if block {
            return self.rzrecv.recv().map_err(|_| "Channel recv error");
        }
        self.rzrecv.try_recv().map_err(|_| "Channel try_recv error")
    }
}

impl RzPipeSpawn {
    pub fn cmd(&mut self, cmd: &str) -> Result<String, String> {
        let cmd = cmd.to_owned() + "\n";
        self.write
            .write_all(cmd.as_bytes())
            .map_err(|e| e.to_string())?;

        let mut res: Vec<u8> = Vec::new();
        self.read
            .read_until(0u8, &mut res)
            .map_err(|e| e.to_string())?;
        process_result(res)
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value, String> {
        let result = self.cmd(cmd)?;
        if result == "" {
            return Err("Empty JSON".to_string());
        }
        serde_json::from_str(&result).map_err(|e| e.to_string())
    }

    pub fn close(&mut self) {
        let _ = self.cmd("q!");
    }
}

impl RzPipeLang {
    pub fn cmd(&mut self, cmd: &str) -> Result<String, String> {
        self.write.write_all(cmd.as_bytes()).unwrap();
        let mut res: Vec<u8> = Vec::new();
        self.read.read_until(0u8, &mut res).unwrap();
        process_result(res)
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value, String> {
        let res = self.cmd(cmd)?;

        serde_json::from_str(&res).map_err(|e| e.to_string())
    }

    pub fn close(&mut self) {
        // self.read.close();
        // self.write.close();
    }
}

impl RzPipeHttp {
    pub fn cmd(&mut self, cmd: &str) -> Result<String, String> {
        let url = format!("http://{}/cmd/{}", self.host, cmd);
        let res = reqwest::get(&url).unwrap();
        let bytes = res.bytes().filter_map(|e| e.ok()).collect::<Vec<_>>();
        str::from_utf8(bytes.as_slice())
            .map(|s| s.to_string())
            .map_err(|err| err.to_string())
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value, String> {
        let res = self.cmd(cmd)?;
        serde_json::from_str(&res).map_err(|e| format!("Unable to parse json: {}", e))
    }

    pub fn close(&mut self) {}
}

impl RzPipeTcp {
    pub fn cmd(&mut self, cmd: &str) -> Result<String, String> {
        let mut stream = TcpStream::connect(self.socket_addr)
            .map_err(|e| format!("Unable to connect TCP stream: {}", e))?;
        stream
            .write_all(cmd.as_bytes())
            .map_err(|e| format!("Unable to write to TCP stream: {}", e))?;
        let mut res: Vec<u8> = Vec::new();
        stream
            .read_to_end(&mut res)
            .map_err(|e| format!("Unable to read from TCP stream: {}", e))?;
        res.push(0);
        process_result(res)
    }

    pub fn cmdj(&mut self, cmd: &str) -> Result<Value, String> {
        let res = self.cmd(cmd)?;
        serde_json::from_str(&res).map_err(|e| format!("Unable to parse json: {}", e))
    }

    pub fn close(&mut self) {}
}

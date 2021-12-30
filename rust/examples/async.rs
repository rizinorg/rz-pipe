use rzpipe::RzPipe;

use std::sync::mpsc::channel;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;

const FILENAME: &str = "/bin/ls";

pub struct RzPipeAsync {
    tx: Sender<String>,
    rx: Receiver<String>,
    tx2: Sender<String>,
    rx2: Receiver<String>,
    cbs: Vec<Arc<dyn Fn(String)>>,
}

impl RzPipeAsync {
    pub fn open() -> RzPipeAsync {
        let (tx, rx) = channel(); // query
        let (tx2, rx2) = channel(); // result
        RzPipeAsync {
            tx,
            rx,
            tx2,
            rx2,
            cbs: Vec::new(),
        }
    }

    pub fn cmd(&mut self, str: &'static str, cb: Arc<dyn Fn(String)>) {
        self.cbs.insert(0, cb);
        self.tx.send(str.to_string()).unwrap();
    }

    pub fn quit(&mut self) {
        self.tx.send("q".to_string()).unwrap();
    }

    pub fn mainloop(mut self) {
        let child_rx = self.rx;
        let child_tx = self.tx2.clone();
        let child = thread::spawn(move || {
            let mut rzp = match RzPipe::in_session() {
                Some(_) => RzPipe::open(),
                None => RzPipe::spawn(FILENAME, None),
            }
            .unwrap_or(RzPipe::None);
            loop {
                let msg = child_rx.recv().unwrap();
                if msg == "q" {
                    // push a result without callback
                    child_tx.send("".to_owned()).unwrap();
                    drop(child_tx);
                    break;
                }
                let res = rzp.cmd(&msg).unwrap();
                child_tx.send(res).unwrap();
            }
            rzp.close();
        });

        // main loop
        loop {
            let msg = self.rx2.recv();
            if msg.is_ok() {
                let res = msg.unwrap();
                if let Some(cb) = self.cbs.pop() {
                    cb(res.trim().to_string());
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        child.join().unwrap();
    }
}

fn main() {
    let mut rzpa = RzPipeAsync::open();
    rzpa.cmd(
        "?e One",
        Arc::new(|x| {
            println!("One: {}", x);
        }),
    );
    rzpa.cmd(
        "?e Two",
        Arc::new(|x| {
            println!("Two: {}", x);
        }),
    );
    rzpa.quit();
    rzpa.mainloop();
}

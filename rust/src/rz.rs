// Copyright (c) 2015, The Radare Project. All rights reserved.
// See the COPYING file at the top-level directory of this distribution.
// Licensed under the BSD 3-Clause License:
// <http://opensource.org/licenses/BSD-3-Clause>
// This file may not be copied, modified, or distributed
// except according to those terms.

//! Few functions for initialization, communication and termination of rizin.

use crate::rzpipe::RzPipe;
use serde_json;
use serde_json::Value;

pub struct Rz {
    pipe: RzPipe,
    readin: String,
}

impl Default for Rz {
    fn default() -> Rz {
        Rz::new::<&str>(None).expect("Unable to spawn rizin or find an open rzpipe")
    }
}

// fn send and recv allow users to send their own commands,
// i.e. The ones that are not currently abstracted by the Rizin API.
// Ideally, all commonly used commands must be supported for easier use.
impl Rz {
    // TODO: Use an error type
    pub fn new<T: AsRef<str>>(path: Option<T>) -> Result<Rz, String> {
        if path.is_none() && !Rz::in_session() {
            let e = "No rizin session open. Please specify path.".to_owned();
            return Err(e);
        }

        // This means that path is `Some` or we have an open session.
        let pipe = open_pipe!(path.as_ref()).unwrap();
        Ok(Rz {
            pipe,
            readin: String::new(),
        })
    }

    pub fn in_session() -> bool {
        RzPipe::in_session().is_some()
    }

    pub fn from(rzp: RzPipe) -> Rz {
        Rz {
            pipe: rzp,
            readin: String::new(),
        }
    }

    pub fn close(&mut self) {
        self.send("q!");
    }

    pub fn send(&mut self, cmd: &str) {
        self.readin = self.pipe.cmd(cmd).unwrap();
    }

    pub fn recv(&mut self) -> String {
        let res = self.readin.clone();
        self.flush();
        res
    }

    pub fn recv_json(&mut self) -> Value {
        let mut res = self.recv().replace("\n", "");
        if res.is_empty() {
            res = "{}".to_owned();
        }

        // TODO: this should probably return a Result<Value, Error>
        serde_json::from_str(&res).unwrap()
    }

    pub fn flush(&mut self) {
        self.readin = String::from("");
    }
}

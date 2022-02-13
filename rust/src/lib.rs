//! `RzPipe` provides functions to interact with [rizin](http://rizin.re).
//! This aims to be a raw API. For more higher-level functions and structs to abstract
//! over the generated output, see [rzpipe.rs-frontend]().
//!
//! Hence this requires you to have rizin installed on you system. For more
//! information refer to the rizin [repository](https://github.com/rizinorg/rizin).
//! The module spawns an instance of rizin and communicates with it over pipes.
//! Using commands which produce a JSON output is recommended and easier to
//! parse.
//!
//! `RzPipe`s are available for a several of languages. For more information
//! about rzpipes in general head over to the
//! [wiki](https://github.com/rizinorg/rz-pipe/).
//!
//! # Design
//! All the functionality for the crate are exposed through two structs:
//! `RzPipeLang` and `RzPipeSpawn`.
//!
//! Typically, there are two ways to invoke rzpipe. One by spawning a
//! child-process from inside rizin and second by making the program spawn
//! a child rzprocess. `enum RzPipe` is provided to allow easier use of the
//! library and abstract the difference between these two methods.
//!
//! The `macro open_pipe!()` determines which of the two methods to use.
//!
//! **Note:** For the second method,
//! the path of the executable to be analyzed must be provided, while this is
//! implicit in the first (pass `None`) method (executable loaded by rizin).
//!
//! # Example
//! ```no_run
//! #[macro_use]
//! extern crate rzpipe;
//! extern crate serde_json;
//! use rzpipe::RzPipe;
//! fn main() {
//!     let path = Some("/bin/ls".to_owned());
//!     let mut rzp = open_pipe!(path).unwrap();
//!     println!("{}", rzp.cmd("?e Hello World").unwrap());
//!     if let Ok(json) = rzp.cmdj("ij") {
//!         println!("{}", serde_json::to_string_pretty(&json).unwrap());
//!         println!("ARCH {}", json["bin"]["arch"]);
//!     }
//!     rzp.close();
//! }
//! ```
//!
//! The crate offers various methods to interact with rzpipe, eg. via
//! process (multi-threadable), http or tcp.
//! Check the examples/ dir for more complete examples.

pub use self::errors::{
    RzInitError, RzPipeError, RzPipeHttpError, RzPipeLangError, RzPipeSpawnError, RzPipeTcpError,
    RzPipeThreadError,
};
// Rexport to bring it out one module.
pub use self::rz::Rz;
pub use self::rzpipe::RzPipe;
pub use self::rzpipe::RzPipeSpawnOptions;

#[macro_use]
pub mod rzpipe;
pub mod errors;
pub mod rz;

use serde_json;

use rzpipe::RzPipe;
use rzpipe::RzPipeSpawnOptions;

fn test_trim() {
    let mut ns = RzPipe::spawn("/bin/ls".to_owned(), None).unwrap();
    println!("(({}))", ns.cmd("\n\n?e hello world\n\n").unwrap());
    println!("(({}))", ns.cmd("\n\n?e hello world\n\n").unwrap());
    println!("(({}))", ns.cmd("\n\n?e hello world\n\n").unwrap());
    ns.close();
    //    process::exit(0);
}

fn main() {
    test_trim();

    // let mut rzp = open_pipe!().unwrap();
    let opts = RzPipeSpawnOptions {
        exepath: "rizin".to_owned(),
        ..Default::default()
    };
    let mut rzp = match RzPipe::in_session() {
        Some(_) => RzPipe::open(),
        None => RzPipe::spawn("/bin/ls".to_owned(), Some(opts)),
    }
    .unwrap();

    println!("{}", rzp.cmd("?e Hello World").unwrap());

    let json = rzp.cmdj("ij").unwrap();
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
    println!("Disasm:\n{}", rzp.cmd("pd 20").unwrap());
    println!("Hexdump:\n{}", rzp.cmd("px 64").unwrap());
    rzp.close();
}

use serde_json;

use rzpipe::RzPipe;
use std::sync::Arc;

  fn main() {
    // First we define a callback. It doesn't block and gets called after a thread receives output from rzpipe
    // Note: First argument to the callback is the thread id, second one the rzpipe output
    let callback = Arc::new(|id, result| {
        println!("Pipe #{} says: {}", id, result);
    });

    // First two arguments for RzPipe::threads() are the same as for RzPipe::spawn() but inside vectors
    // Third and last argument is an option to a callback function
    // The callback function takes two Arguments: Thread ID and rzpipe output
    let pipes = match RzPipe::threads(
        vec!["/bin/ls", "/bin/id", "/bin/cat"],
        vec![None, None, None],
        Some(callback),
        ) {
        Ok(p) => p,
        Err(e) => {
            println!("Error spawning Pipes: {}", e);
            return;
        }
    };

    // At this point we can iter through all of our rzpipes and send some commands
    for p in pipes.iter() {
        if let Ok(_) = p.send("ij".to_string()) {};
    }

    // Meanwhile: Expecting callbacks
    std::thread::sleep(std::time::Duration::from_millis(1000));

    // Finally properly close all pipes
    // Note: For "join()" we need to borrow so pipes.iter() won't work for this
    for p in pipes {
        if let Ok(_) = p.send("q".to_string()) {};
        p.handle.join().unwrap();
    }
}

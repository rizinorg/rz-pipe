use rzpipe::RzPipe;

fn main() {
    // Let's spawn some rzpipes to open some binaries
    // First two arguments for RzPipe::threads() are the same as for RzPipe::spawn() but inside vectors
    // Third and last argument is an option of a callback function
    let pipes = match RzPipe::threads(
        vec!["/bin/ls", "/bin/cat", "/bin/less"],
        vec![None, None, None],
        None,
    ) {
        Ok(p) => p,
        Err(e) => {
            println!("Error spawning Pipes: {}", e);
            return;
        }
    };

    // At this point we can iter through all of our rzpipes and send some commands
    for p in pipes.iter() {
        if p.send("ij".to_string()).is_ok() {};
    }

    // do_other_stuff_here();

    // Let's iter again and see what the pipes got
    for p in pipes.iter() {
        // this will block, do "p.recv(false)" for non-blocking receive inside a loop
        if let Ok(msg) = p.recv(true) {
            println!("Pipe #{} says: {}", p.id, msg);
        }
    }

    // Finally properly close all pipes
    // Note: For "join()" we need to borrow so pipes.iter() won't work for this
    for p in pipes {
        if p.send("q".to_string()).is_ok() {};
        p.handle.join().unwrap();
    }
}

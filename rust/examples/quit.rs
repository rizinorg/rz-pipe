use rzpipe::RzPipe;

fn main() {
    let mut rzp = RzPipe::spawn("/bin/ls", None).unwrap();
    println!("{}", rzp.cmd("?e Hello").unwrap());
    if let Err(_) = rzp.cmd("q") {
        // !killall rz") {
        println!("Quit happens!");
    } else {
        println!("Quit failed/ignored!");
        if let Ok(msg) = rzp.cmd("?e World") {
            println!("{}", msg);
            rzp.close();
        } else {
            println!("FAIL");
        }
    }
    println!("Bye!");
}

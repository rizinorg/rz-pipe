use serde_json;
use rzpipe::RzPipe;

fn main() {
	let mut rzp = RzPipe::http("localhost:9080").unwrap();

	let json = rzp.cmdj("ij").unwrap();
	println!("{}", serde_json::to_string_pretty(&json).unwrap());
	println!("ARCH {}", json["bin"]["arch"]);
	println!("BITS {}", json["bin"]["bits"]);
	println!("Disasm:\n{}", rzp.cmd("pd 20").unwrap());
	println!("Hexdump:\n{}", rzp.cmd("px 64").unwrap());
	rzp.close();
}

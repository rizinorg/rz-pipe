all: main quit brokenpipe test tcp threads async

main:
	rustc -L ../target/debug/ -L ../target/debug/deps main.rs 
	rizin -qc '#!pipe ./main' /bin/ls

brokenpipe:
	rustc -L ../target/debug/ -L ../target/debug/deps brokenpipe.rs

async:
	rustc -L ../target/debug/ -L ../target/debug/deps async.rs

http:
	rustc -L ../target/debug/ -L ../target/debug/deps http.rs

threads:
	rustc -L ../target/debug/ -L ../target/debug/deps threads.rs
	rustc -L ../target/debug/ -L ../target/debug/deps threads_callback.rs

tcp:
		rustc -L ../target/debug/ -L ../target/debug/deps tcp.rs

quit:
	rustc -L ../target/debug/ -L ../target/debug/deps quit.rs 
	rizin -qc '#!pipe ./quit' /bin/ls

.PHONY: main quit async brokenpipe

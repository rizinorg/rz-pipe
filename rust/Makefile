all:
	cargo build

clean:
	cargo clean

doc:
	cargo doc --no-deps

run:
	rizin -qc '#!pipe target/debug/rzpipe' /bin/ls
	target/debug/rzpipe

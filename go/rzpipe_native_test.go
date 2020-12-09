// rizin - LGPL - Copyright 2017 - pancake

package rzpipe

import "testing"

func TestNativeCmd(t *testing.T) {
	rzp, err := NewNativePipe("/bin/ls")
	// rzp, err := NewPipe("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	defer rzp.Close()
	version, err := rzp.Cmd("pd 10 @ entry0")
	if err != nil {
		t.Fatal(err)
	}
	print(version + "\n")
}

// rizin - LGPL - Copyright 2015 - nibble

package rzpipe

import "testing"

func TestCmd(t *testing.T) {
	rzp, err := NewPipe("malloc://256")
	if err != nil {
		t.Fatal(err)
	}
	defer rzp.Close()

	check := "Hello World"

	_, err = rzp.Cmd("w " + check)
	if err != nil {
		t.Fatal(err)
	}
	buf, err := rzp.Cmd("ps")
	if err != nil {
		t.Fatal(err)
	}
	if buf != check {
		t.Errorf("buf=%v; want=%v", buf, check)
	}
}

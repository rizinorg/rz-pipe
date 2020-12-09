// rizin - LGPL - Copyright 2017 - pancake

package main

import (
	"fmt"

	".."
)

func main() {
	rzp, err := rzpipe.NewPipe("/bin/ls")
	if err != nil {
		print("ERROR: ", err)

		return
	}

	disasm, err := rzp.Cmd("pd 20")
	if err != nil {
		print("ERROR: ", err)
	} else {
		print(disasm, "\n")
	}

	err = rzp.Close()
	if err != nil {
		panic(fmt.Sprintf("Error closing rzpipe: %s", err))
	}
}

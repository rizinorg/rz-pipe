// rizin - LGPL - Copyright 2017 - pancake

package main

import (
	"os"
	"fmt"
	"github.com/rizinorg/rz-pipe/go"
)

func isInRizin() (bool){
	rzpipeIn := os.Getenv("RZ_PIPE_IN")
	rzpipeOut := os.Getenv("RZ_PIPE_OUT")


	if rzpipeIn == "" || rzpipeOut == "" {
		return false
	}

	return true
}

func main() {
	path := "/bin/ls"
	if isInRizin() {
		path = ""
	}

	r2p, err := rzpipe.NewPipe(path)
	if err != nil {
		panic(err)
	}
	defer r2p.Close()

	_, err = r2p.Cmd("aaaa")
	if err != nil {
		panic(err)
	}
	buf, err := r2p.Cmd("pi 10")
	if err != nil {
		panic(err)
	}
	fmt.Println(buf)
	fmt.Println("done")
}


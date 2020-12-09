// rizin - LGPL - Copyright 2015 - nibble

/*
Package rzpipe allows to call rizin commands from Go. A simple hello world would
look like the following snippet:

	package main

	import (
		"fmt"
		"github.com/rizin/rz-pipe-go"
	)

	func main() {
		rzp, err := rzpipe.NewPipe("malloc://256")
		if err != nil {
			panic(err)
		}
		defer rzp.Close()

		_, err = rzp.Cmd("w Hello World")
		if err != nil {
			panic(err)
		}
		buf, err := rzp.Cmd("ps")
		if err != nil {
			panic(err)
		}
		fmt.Println(buf)
	}
*/
package rzpipe

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// A Pipe represents a communication interface with rizin that will be used to
// execute commands and obtain their results.
type Pipe struct {
	File   string
	rzcmd  *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	Core   *struct{}
	cmd    CmdDelegate
	close  CloseDelegate
}

type (
	CmdDelegate   func(*Pipe, string) (string, error)
	CloseDelegate func(*Pipe) error
)

// NewPipe returns a new rizin pipe and initializes an rizin core that will try to
// load the provided file or URI. If file is an empty string, the env vars
// RZPIPE_{IN,OUT} will be used as file descriptors for input and output, this
// is the case when rz-pipe is called within rizin.
func NewPipe(file string) (*Pipe, error) {
	if file == "" {
		return newPipeFd()
	}

	return newPipeCmd(file)
}

func newPipeFd() (*Pipe, error) {
	rzpipeIn := os.Getenv("RZPIPE_IN")
	rzpipeOut := os.Getenv("RZPIPE_OUT")

	if rzpipeIn == "" || rzpipeOut == "" {
		return nil, fmt.Errorf("missing RZPIPE_{IN,OUT} vars")
	}

	rzpipeInFd, err := strconv.Atoi(rzpipeIn)
	if err != nil {
		return nil, fmt.Errorf("failed to convert IN into file descriptor")
	}

	rzpipeOutFd, err := strconv.Atoi(rzpipeOut)
	if err != nil {
		return nil, fmt.Errorf("failed to convert OUT into file descriptor")
	}

	stdout := os.NewFile(uintptr(rzpipeInFd), "RZPIPE_IN")
	stdin := os.NewFile(uintptr(rzpipeOutFd), "RZPIPE_OUT")

	rzp := &Pipe{
		File:   "",
		rzcmd:  nil,
		stdin:  stdin,
		stdout: stdout,
		Core:   nil,
	}

	return rzp, nil
}

func newPipeCmd(file string) (*Pipe, error) {
	rzcmd := exec.Command("rizin", "-q0", file)

	stdin, err := rzcmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	stdout, err := rzcmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := rzcmd.Start(); err != nil {
		return nil, err
	}

	// Read initial data
	if _, err := bufio.NewReader(stdout).ReadString('\x00'); err != nil {
		return nil, err
	}

	rzp := &Pipe{
		File:   file,
		rzcmd:  rzcmd,
		stdin:  stdin,
		stdout: stdout,
		Core:   nil,
	}

	return rzp, nil
}

// Write implements the standard Write interface: it writes data to the rizin
// pipe, blocking until rizin have consumed all the data.
func (rzp *Pipe) Write(p []byte) (n int, err error) {
	return rzp.stdin.Write(p)
}

// Read implements the standard Read interface: it reads data from the rizin
// pipe, blocking until the previously issued commands have finished.
func (rzp *Pipe) Read(p []byte) (n int, err error) {
	return rzp.stdout.Read(p)
}

// Cmd is a helper that allows to run rizin commands and receive their output.
func (rzp *Pipe) Cmd(cmd string) (string, error) {
	if rzp.Core != nil {
		if rzp.cmd != nil {
			return rzp.cmd(rzp, cmd)
		}

		return "", nil
	}

	if _, err := fmt.Fprintln(rzp, cmd); err != nil {
		return "", err
	}

	buf, err := bufio.NewReader(rzp).ReadString('\x00')
	if err != nil {
		return "", err
	}

	return strings.TrimRight(buf, "\n\x00"), nil
}

// Cmdj acts like Cmd but interprets the output of the command as json. It
// returns the parsed json keys and values.
func (rzp *Pipe) Cmdj(cmd string) (interface{}, error) {
	if _, err := fmt.Fprintln(rzp, cmd); err != nil {
		return nil, err
	}

	buf, err := bufio.NewReader(rzp).ReadBytes('\x00')
	if err != nil {
		return nil, err
	}

	buf = bytes.TrimRight(buf, "\n\x00")

	var output interface{}

	if err := json.Unmarshal(buf, &output); err != nil {
		return nil, err
	}

	return output, nil
}

// Close shuts down rz, closing the created pipe.
func (rzp *Pipe) Close() error {
	if rzp.close != nil {
		return rzp.close(rzp)
	}

	if rzp.File == "" {
		return nil
	}

	if _, err := rzp.Cmd("q"); err != nil {
		return err
	}

	return rzp.rzcmd.Wait()
}

// Forcing shutdown of rz, closing the created pipe.
func (rzp *Pipe) ForceClose() error {
	if rzp.close != nil {
		return rzp.close(rzp)
	}

	if rzp.File == "" {
		return nil
	}

	if _, err := rzp.Cmd("q!"); err != nil {
		return err
	}

	return rzp.rzcmd.Wait()
}

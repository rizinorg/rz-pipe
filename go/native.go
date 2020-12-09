// rizin - LGPL - Copyright 2017 - pancake

package rzpipe

import (
	"github.com/rainycape/dl"
	"errors"
)

type Ptr = *struct{}

var (
	lib            Ptr = nil
	rz_core_new     func() Ptr
	rz_core_free    func(Ptr)
	rz_mem_free     func(interface{})
	rz_core_cmd_str func(Ptr, string) string
)

func NativeLoad() error {
	if lib != nil {
		return nil
	}
	lib, err := dl.Open("librz_core", 0)
	if err != nil {
		return err
	}
	if lib.Sym("rz_core_new", &rz_core_new) != nil {
		return errors.New("Missing rz_core_new")
	}
	if lib.Sym("rz_core_cmd_str", &rz_core_cmd_str) != nil {
		return errors.New("Missing rz_core_cmd_str")
	}
	if lib.Sym("rz_core_free", &rz_core_free) != nil {
		return errors.New("Missing rz_core_free")
	}
	if lib.Sym("rz_mem_free", &rz_mem_free) != nil {
		return errors.New("Missing rz_mem_free")
	}
	return nil
}

func (rzp *Pipe) NativeCmd(cmd string) (string, error) {
	res := rz_core_cmd_str(rzp.Core, cmd)
	return res, nil
}

func (rzp *Pipe) NativeClose() error {
	rz_core_free(rzp.Core)
	rzp.Core = nil
	return nil
}

func NewNativePipe(file string) (*Pipe, error) {
	if err := NativeLoad(); err != nil {
		return nil, err
	}
	rz := rz_core_new()
	rzp := &Pipe{
		File: file,
		Core: rz,
		cmd: func(rzp *Pipe, cmd string) (string, error) {
			return rzp.NativeCmd(cmd)
		},
		close: func(rzp *Pipe) error {
			return rzp.NativeClose()
		},
	}
	if file != "" {
		rzp.NativeCmd("o " + file)
	}
	return rzp, nil
}

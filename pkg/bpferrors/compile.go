package bpferrors

import (
	"errors"
)

var ErrBadModuleBuild = errors.New("unable to compile bpf src")

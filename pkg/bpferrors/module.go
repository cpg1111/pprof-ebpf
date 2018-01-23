package bpferrors

import (
	"errors"
)

var (
	ErrBadModuleBuild   = errors.New("unable to compile bpf src")
	ErrNoTableNameFound = errors.New("no table name found")
)

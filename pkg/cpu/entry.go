package cpu

import (
	"github.com/cpg1111/pprof-ebpf/pkg/bpferrors"
)

type HeaderEntry struct {
	Name     string
	FD       int64
	KeySize  int64
	LeafSize int64
	KeyDesc  interface{}
	LeafDesc interface{}
}

func Format(header map[string]interface{}) (string, error) {
	for k, v := range header {
		if k == "name" {
			return v.(string), nil
		}
	}
	return "", bpferrors.ErrNoTableNameFound
}

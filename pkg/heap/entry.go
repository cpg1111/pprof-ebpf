package heap

import (
	"github.com/cpg1111/pprof-ebpf/pkg/bpferrors"
)

func Format(header map[string]interface{}) (string, error) {
	for k, v := range header {
		if k == "name" {
			return v.(string), nil
		}
	}
	return "", bpferrors.ErrNoTableNameFound
}

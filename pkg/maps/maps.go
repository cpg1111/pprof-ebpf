package maps

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
)

type ProcMap struct {
	Start    uint64
	Stop     uint64
	Offset   uint64
	Dev      string
	Flags    string
	INode    uint64
	PathName string
}

func (p *ProcMap) Contains(addr uint64) bool {
	return p.Start <= addr && p.Stop >= addr
}

func Contains(maps []*ProcMap, addr uint64) bool {
	for _, m := range maps {
		if m.Contains(addr) {
			return true
		}
	}
	return false
}

func GetByPID(pid int) (res []*ProcMap, err error) {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return Parse(f)
}

func Parse(f io.Reader) (res []*ProcMap, err error) {
	buf := bufio.NewReader(f)
	for l, _, err := buf.ReadLine(); err != io.EOF; l, _, err = buf.ReadLine() {
		if len(l) == 0 {
			continue
		}
		if err != nil {
			return nil, err
		}
		list := bytes.Split(l, []byte(" "))
		startStop := bytes.Split(list[0], []byte("-"))
		start, err := strconv.ParseUint("0x"+string(startStop[0]), 0, 64)
		if err != nil {
			return nil, err
		}
		stop, err := strconv.ParseUint("0x"+string(startStop[1]), 0, 64)
		if err != nil {
			return nil, err
		}
		offset, err := strconv.ParseUint("0x"+string(list[2]), 0, 64)
		if err != nil {
			return nil, err
		}
		iNode, err := strconv.ParseUint(string(list[4]), 0, 64)
		if err != nil {
			return nil, err
		}
		pMap := &ProcMap{
			Start:    start,
			Stop:     stop,
			Flags:    string(list[1]),
			Offset:   offset,
			Dev:      string(list[3]),
			INode:    iNode,
			PathName: string(bytes.TrimSpace(list[len(list)-1])),
		}
		res = append(res, pMap)
	}
	return
}

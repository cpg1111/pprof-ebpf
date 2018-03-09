package maps

import (
	"bytes"
	"testing"
)

const testMap = `
7ff84af3e000-7ff84b114000 r-xp 00000000 fd:00 1835497                    /lib/x86_64-linux-gnu/libc-2.26.so
7ff84b114000-7ff84b314000 ---p 001d6000 fd:00 1835497                    /lib/x86_64-linux-gnu/libc-2.26.so
7ff84b314000-7ff84b318000 r--p 001d6000 fd:00 1835497                    /lib/x86_64-linux-gnu/libc-2.26.so
7ff84b318000-7ff84b31a000 rw-p 001da000 fd:00 1835497                    /lib/x86_64-linux-gnu/libc-2.26.so
`

func TestParse(t *testing.T) {
	buf := bytes.NewBufferString(testMap)
	maps, err := Parse(buf)
	if err != nil {
		t.Error(err)
	}
	for i, m := range maps {
		switch i {
		case 0:
			if m.Start != uint64(0x7ff84af3e000) {
				t.Errorf("expected 7ff84af3e000 found %d", m.Start)
			}
			if m.Stop != uint64(0x7ff84b114000) {
				t.Errorf("expected 7ff84b114000 found %d", m.Stop)
			}
			if m.Offset != uint64(0) {
				t.Errorf("expected 0 found %d", m.Offset)
			}
			if m.Flags != "r-xp" {
				t.Errorf("expected r-xp found %s", m.Flags)
			}
			if m.Dev != "fd:00" {
				t.Errorf("expected fd:00 found %s", m.Dev)
			}
			if m.INode != 1835497 {
				t.Errorf("expected 1835497 found %d", m.INode)
			}
			if m.PathName != "/lib/x86_64-linux-gnu/libc-2.26.so" {
				t.Errorf("expected /lib/x86_64-linux-gnu/libc-2.26.so found %s", m.PathName)
			}
		}
	}
}

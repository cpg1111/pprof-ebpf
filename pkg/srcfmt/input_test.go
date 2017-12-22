package srcfmt

import (
	"testing"
)

type testData struct {
	Msg string
}

func TestProcessSrc(t *testing.T) {
	input := "{{.Msg}}"
	output := "Hello, World!"
	buf, err := ProcessSrc(input, testData{Msg: "Hello, World!"})
	if err != nil {
		t.Error(err)
	}
	res := buf.String()
	if res != output {
		t.Errorf("expected %s, found %s", output, res)
	}
}

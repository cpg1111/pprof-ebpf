package srcfmt

import (
	"bytes"
	"text/template"
)

func ProcessSrc(src string, data interface{}) (buf *bytes.Buffer, err error) {
	buf = bytes.NewBuffer(nil)
	tmpl := template.New("script")
	tmpl, err = tmpl.Parse(src)
	if err != nil {
		return nil, err
	}
	err = tmpl.Execute(buf, data)
	if err != nil {
		return nil, err
	}
	return
}

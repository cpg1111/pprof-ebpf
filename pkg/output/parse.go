package output

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	bpf "github.com/iovisor/gobpf/bcc"
	log "github.com/sirupsen/logrus"
)

type FormatFunc func(map[string]interface{}) (string, error)

type Parser struct {
	mod  *bpf.Module
	stop chan struct{}
}

func NewParser(mod *bpf.Module) *Parser {
	return &Parser{
		mod:  mod,
		stop: make(chan struct{}),
	}
}

func (p *Parser) parseHexString(raw string) ([]byte, error) {
	ret := ""
	for _, c := range strings.Split(strings.Replace(raw, "0x", "", -1), " ") {
		if c == "[" || c == "]" {
			continue
		}
		if c == "0" {
			break
		}
		ret = fmt.Sprintf("%s%s", ret, c)
	}
	return hex.DecodeString(ret)
}

func (p *Parser) parseHexInt(raw string) (uint64, error) {
	return strconv.ParseUint(raw, 0, 64)
}

func (p *Parser) Parse(ctx context.Context, format FormatFunc) (err error) {
	println("inside")
	out := make(chan []byte)
	defer p.mod.Close()
	for e := range p.mod.TableIter() {
		go func(entry map[string]interface{}) {
			println("disbitch")
			tableName, err := format(entry)
			if err != nil {
				println(err)
				//	return err
			}
			println("dem tables")
			table := bpf.NewTable(p.mod.TableId(tableName), p.mod)
			println("buildin tables")
			perfMap, err := bpf.InitPerfMap(table, out)
			println("I gots the map")
			if err != nil {
				println(err)
				//	return err
			}
			perfMap.Start()
			<-ctx.Done()
			perfMap.Stop()

		}(e)
	}
	for o := range out {
		println("mhm")
		log.Info(string(o))
	}
	return nil
}

func (p *Parser) Stop() {
	p.stop <- struct{}{}
}

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
	defer p.mod.Close()
	for entry := range p.mod.TableIter() {
		tableName, err := format(entry)
		if err != nil {
			return err
		}
		table := bpf.NewTable(p.mod.TableId(tableName), p.mod)
		tableConf := table.Config()
		if tableConf["key_size"].(uint64) == 4 && tableConf["leaf_size"].(uint64) == 4 {
			out := make(chan []byte)
			fmt.Printf("%+v\n", table.Config())
			perfMap, err := bpf.InitPerfMap(table, out)
			if err != nil {
				return err
			}
			go perfMap.Start()
			for o := range out {
				log.Info(string(o))
			}
			perfMap.Stop()
		} else {
			entries := table.Iter()
			for entry := range entries {
				fmt.Printf("key %s, value %s\n", entry.Key, entry.Value)
			}
		}
	}
	return nil
}

func (p *Parser) Stop() {
	p.stop <- struct{}{}
}

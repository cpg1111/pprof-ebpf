package output

import (
	"encoding/hex"
	"fmt"
	"reflect"
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

func (p *Parser) Parse(format FormatFunc) (err error) {
	var tables []*bpf.Table
	selectCases := []reflect.SelectCase{
		reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(p.stop),
		},
	}
	defer p.mod.Close()
	for entry := range p.mod.TableIter() {
		tableName, err := format(entry)
		if err != nil {
			return err
		}
		table := bpf.NewTable(p.mod.TableId(tableName), p.mod)
		tables = append(tables, table)
		selectCases = append(selectCases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(table.Iter()),
		})
	}
	for {
		idx, val, recv := reflect.Select(selectCases)
		if idx == 0 {
			if recv {
				return
			}
		} else if recv {
			table := tables[idx-1]
			log.Info(table.Name())
			entry := val.Interface().(bpf.Entry)
			var key, value interface{}
			key, err = p.parseHexInt(entry.Key)
			if err != nil {
				origErr := err
				key, err = p.parseHexString(entry.Key)
				if err != nil {
					return fmt.Errorf("%s and %s", origErr, err)
				}
			}
			value, err = p.parseHexInt(entry.Value)
			if err != nil {
				origErr := err
				value, err = p.parseHexString(entry.Value)
				if err != nil {
					return fmt.Errorf("%s and %s", origErr, err)
				}
			}
			log.WithFields(log.Fields{
				"key":   key,
				"value": value,
			}).Infof("entry: %s\n", table.Name())
		}
	}
	return nil
}

func (p *Parser) Stop() {
	p.stop <- struct{}{}
}

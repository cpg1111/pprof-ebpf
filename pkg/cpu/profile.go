package cpu

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"

	"github.com/cpg1111/pprof-ebpf/pkg/srcfmt"
)

import "C"

const (
	bpfSRC = `
	#include <uapi/linux/ptrace.h>
	#include <bcc/proto.h>
	
	typedef struct {
		u32 pid;
		uid_t uid;
		gid_t gid;
		int ret;
		char filename[{{.FileNameLen}}];
	} {{.EventName}}_event_t;

	BPF_PERF_OUTPUT({{.EventName}}_event);
	BPF_HASH({{.EventCall}}, u64, {{.EventName}}_event_t);

	int kprobe__{{.KFuncCall}}(struct pt_regs *ctx, int dfd, const char *filename,
							uid_t uid, gid_t gid, int flag)
	{
		u64 pid = bpf_get_current_pid_tgid();
		{{.EventName}}_event_t event = {
			.pid = pid >> 32,
			.uid = uid,
			.gid = gid,												
		};
		bpf_probe_read(&event.filename, sizeof(event.filename), (void *)filename);
		{{.EventCall}}.update(&pid, &event);
		return 0;
	}
	
	int kretprobe__{{.KFuncCall}}(struct pt_regs *ctx)
	{
		int ret = PT_REGS_RC(ctx);
		u64 pid = bpf_get_current_pid_tgid();
		{{.EventName}}_event_t *eventp = {{.EventCall}}.lookup(&pid);
		if (eventp == 0) {
			return 0;
		}
		{{.EventName}}_event_t event = *eventp;
		event.ret = ret;
		{{.EventName}}_event.perf_submit(ctx, &event, sizeof(event));
		{{.EventCall}}.delete(&pid);
		return 0;
	}
`
)

type srcTMPL struct {
	FileNameLen int
	EventName   string
	EventCall   string
	KFuncCall   string
}

type event struct {
	Pid         uint32
	Uid         uint32
	Gid         uint32
	ReturnValue int32
	Filename    [256]byte
}

func Run() {
	eventStr := "chown"
	tmplData := &srcTMPL{
		FileNameLen: 256,
		EventName:   eventStr,
		EventCall:   eventStr + "call",
		KFuncCall:   "_sys_fchownat",
	}
	script, err := srcfmt.ProcessSrc(bpfSRC, tmplData)
	if err != nil {
		println(err.Error())
	}
	mod := bpf.NewModule(script.String(), nil)
	defer mod.Close()
	probe, err := mod.LoadKprobe("kprobe_" + tmplData.KFuncCall)
	if err != nil {
		println(err.Error())
	}
	err = mod.AttachKprobe(tmplData.KFuncCall, probe)
	if err != nil {
		println(err.Error())
	}
	println("tracing...")
	channel := make(chan []byte)
	table := bpf.NewTable(mod.TableId(eventStr+"_events"), mod)
	perfMap, err := bpf.InitPerfMap(table, channel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		return
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var ev event
		for data := range channel {
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &ev)
			if err != nil {
				println(err.Error())
				continue
			}
			filename := (*C.char)(unsafe.Pointer(&ev.Filename))
			fmt.Printf(
				"uid %d gid %d pid %d called fchownat(2) on %s (return value: %d)\n",
				ev.Uid,
				ev.Gid,
				ev.Pid,
				C.GoString(filename),
				ev.ReturnValue,
			)
		}
	}()

	perfMap.Start()
	defer perfMap.Stop()
	<-sig
}

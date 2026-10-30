package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "embed"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cflags "$BPF_CFLAGS" bpf tracer.c

type bpfEvent struct {
	Pid         uint32
	Uid         uint32
	CipherSuite uint16
	Comm        [16]byte
}

func main() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed removing memlock: %s", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("failed loading object BPF: %s", err)
	}
	defer objs.Close()

	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_read", objs.HandleEnterRead, nil)
	if err != nil {
		log.Fatalf("failed attach tracepoint: %s", err)
	}
	defer tpEnter.Close()

	tpExit, err := link.Tracepoint("syscalls", "sys_exit_read", objs.HandleExitRead, nil)
	if err != nil {
		log.Fatalf("failed attach tracepoint: %s", err)
	}
	defer tpExit.Close()

	log.Println("tracing ....")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("failed creating reader ringbuf: %s", err)
	}
	defer rd.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		rd.Close()
	}()

	// Ring Buffer consuming loop
	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("ringbuf closed")
				return
			}
			log.Printf("failed reading ringbuf: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("failed to decode event structure: %s", err)
			continue
		}

		comm := string(bytes.Trim(event.Comm[:], "\x00"))

		log.Printf("[EVENT] PID: %-6d | UID: %-5d | COMM: %s | CIPHER 0x%04X", event.Pid, event.Uid, comm, event.CipherSuite)
	}
}

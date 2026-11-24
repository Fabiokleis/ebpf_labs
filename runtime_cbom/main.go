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

const maxPayload = 4096

type bpfEvent struct {
	Pid         uint32
	Fd          uint32
	OrigLen     uint32
	CapturedLen uint32
	Comm        [16]byte
	Payload     [maxPayload]byte
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

	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_write", objs.HandleEnterWrite, nil)
	if err != nil {
		log.Fatalf("failed attach tracepoint: %s", err)
	}
	defer tpEnter.Close()

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

		capLen := event.CapturedLen
		if capLen > maxPayload {
			capLen = maxPayload
		}

		payload := event.Payload[:capLen]

		// Ignore client messages (0x01, 0x10) and NewSessionTicket (0x04)
		if len(payload) < 6 || payload[5] != 0x02 {
			continue
		}

		hs, err := ParseHandshake(payload)
		if err != nil {
			log.Printf("[WARN] PID: %-6d | FD: %-4d | COMM: %s | %s", event.Pid, event.Fd, comm, err)
			continue
		}

		log.Printf("[EVENT] PID: %-6d | FD: %-4d | TLS: %s | CIPHER: %s (0x%04X) | GROUP: %s (0x%04X) [%s]",
			event.Pid, event.Fd, hs.TLSVersion, hs.CipherName, hs.CipherID, hs.GroupName, hs.GroupID, hs.GroupStatus)
	}
}

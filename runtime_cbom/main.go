package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

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

type connKey struct {
	Pid uint32
	Fd  uint32
}

type activeFlight struct {
	Info     *HandshakeInfo
	LastSeen time.Time
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("failed removing memlock", "err", err)
		os.Exit(1)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		slog.Error("failed loading BPF objects", "err", err)
		os.Exit(1)
	}
	defer objs.Close()

	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_write", objs.HandleEnterWrite, nil)
	if err != nil {
		slog.Error("failed attaching tracepoint", "err", err)
		os.Exit(1)
	}
	defer tpEnter.Close()

	slog.Info("tracing started", "tracepoint", "syscalls/sys_enter_write")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		slog.Error("failed creating ringbuf reader", "err", err)
		os.Exit(1)
	}
	defer rd.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		rd.Close()
	}()

	var mu sync.Mutex
	flights := make(map[connKey]*activeFlight)

	go func() {
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			now := time.Now()
			for k, f := range flights {
				if now.Sub(f.LastSeen) > 300*time.Millisecond {
					f.Info.CloseReason = "timeout"
					logFlight(f.Info)
					delete(flights, k)
				}
			}
			mu.Unlock()
		}
	}()

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				slog.Info("ringbuf closed")
				return
			}
			slog.Error("failed reading ringbuf", "err", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			slog.Error("failed decoding event", "err", err)
			continue
		}

		comm := string(bytes.Trim(event.Comm[:], "\x00"))
		capLen := min(event.CapturedLen, maxPayload)
		payload := event.Payload[:capLen]

		if len(payload) < 6 {
			continue
		}

		key := connKey{Pid: event.Pid, Fd: event.Fd}
		mu.Lock()
		f, exists := flights[key]
		if !exists {
			if payload[5] != hsServerHello {
				mu.Unlock()
				continue
			}
			f = &activeFlight{
				Info: NewHandshakeInfo(event.Pid, event.Fd, comm),
			}
			flights[key] = f
		}

		f.Info.OrigLen += event.OrigLen
		f.Info.CapLen += capLen
		if event.OrigLen > capLen {
			f.Info.Truncated = true
		}
		f.LastSeen = time.Now()

		ParseRecords(payload, f.Info, event.OrigLen)
		if f.Info.Complete {
			logFlight(f.Info)
			delete(flights, key)
		}
		mu.Unlock()
	}
}

func logFlight(hs *HandshakeInfo) {
	slog.Info("flight completed",
		"pid", hs.Pid,
		"fd", hs.Fd,
		"comm", hs.Comm,
		"writes", hs.WriteCount,
		"closed_by", hs.CloseReason,
		"tls", hs.TLSVersion,
		"cipher", hs.CipherName,
		"group", hs.GroupName,
		"group_status", hs.GroupStatus,
		"sig", hs.SigSchemeName,
		"sig_status", hs.SigSchemeStatus,
		"cert", hs.CertSubject,
		"cert_status", hs.CertStatus,
		"truncated", hs.Truncated,
	)
}

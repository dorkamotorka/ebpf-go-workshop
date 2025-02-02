package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 trace portable-kprobe.c

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs traceObjects
	if err := loadTraceObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()
	
	// Attach kprobe 
	kprobe, err := link.Kprobe("__x64_sys_execve", objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("Attaching kProbe: %v", err)
	}
	defer kprobe.Close()

	time.Sleep(time.Second * 15)
}

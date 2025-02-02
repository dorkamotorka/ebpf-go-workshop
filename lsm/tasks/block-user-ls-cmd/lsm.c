//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

#define PATHLEN 256

char _license[] SEC("license") = "GPL";

SEC("lsm/bprm_creds_from_file")
int BPF_PROG(police_perm, struct linux_binprm *bprm, int ret) {
  // Here add your eBPF program code
  // The goal is to block `ls` command for a Linux user with ID 1001
  return 0;
}

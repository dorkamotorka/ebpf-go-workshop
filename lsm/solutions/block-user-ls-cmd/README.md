# Solution: Block `ls` Command for Linux User with ID 1001 using eBPF LSM

**NOTE**: Minimum 5.7 kernel version is required.

In general, before we’re ready to write any LSM-BPF code, we need to find two things:
- Available LSM hook points
- Context provided to the hook point

Unfortunately, I don’t know of any tool that would print this information for us, other than looking directly into the [Linux source code](https://github.com/torvalds/linux/blob/master/security/security.c).

This was already done for you, but you still had to write the code to utilize the context to enforce the policy. Here's the solution:
```
SEC("lsm/bprm_creds_from_file")
int BPF_PROG(police_perm, struct linux_binprm *bprm, int ret) {
  char bl[] = "/usr/bin/ls";
  char buf[PATHLEN];

  __u32 uid =
      bpf_get_current_uid_gid() & 0xFFFFFFFF; // Extract the lower 32 bits (UID)
  int len = bpf_probe_read_str(buf, sizeof(buf), bprm->filename);

  if (uid == 1001 && len > 11) {
    if (buf[0] == bl[0] && buf[1] == bl[1] && buf[2] == bl[2] &&
        buf[3] == bl[3] && buf[4] == bl[4] && buf[5] == bl[5] &&
        buf[6] == bl[6] && buf[7] == bl[7] && buf[8] == bl[8] &&
        buf[9] == bl[9] && buf[10] == bl[10] && buf[11] == bl[11]) {
      bpf_printk("Reject execution of ls command for user with ID %d", uid);
      return -EPERM;
    }
  }

  return 0;
}
``` 

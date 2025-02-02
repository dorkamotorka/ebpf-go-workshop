# Solution: Making Kprobe CO-RE Portable 

The goal was to make kprobe CO-RE portable.

This is achieved by utilizing `PT_REGS_PARM1_CORE` and `bpf_core_read_user_str`:

- `PT_REGS_PARM1_CORE` replaces `PT_REGS_PARM1` and read the first parameters from the registers in a CO-RE relocatable way.
- `bpf_core_read_user_str` replaces `bpf_probe_read_user_str` and read the filename string in a CO-RE relocatable way.

Here's the complete solution:
```
SEC("kprobe/__x64_sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);

    char *filename = (char *)PT_REGS_PARM1_CORE(regs);
    char buf[ARGSIZE];
    bpf_core_read_user_str(buf, sizeof(buf), filename);

    // Print the flags value
    bpf_printk("Kprobe triggered (CO-RE) for execve syscall with parameter filename: %s\n", buf);

    return 0;
}
```

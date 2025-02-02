# Task: Making Kprobe CO-RE Portable

## Why CO-RE?

Compile Once, Run Everywhere (CO-RE) is a critical feature in eBPF development that allows programs to be compiled once and run across different kernel versions without requiring recompilation. 

This is achieved using BTF (BPF Type Format), which provides a way to extract kernel structure layouts dynamically. 

CO-RE enhances portability, reduces dependency on kernel headers, and simplifies deployment, making it ideal for scalable observability and security applications.

Since kprobes can dynamically attach to arbitrary kernel function, which are bound to change across different kernel versions, having CO-RE in-place is absolutely neccessary.

## How to Run

Try and modify the eBPF program to utilize helpers functions like `PT_REGS_PARM1_CORE` and `bpf_core_read_user_str`.

Then you can build and run the eBPF program using:

```
go generate
go build
sudo ./trace
```

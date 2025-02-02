# Task: eBPF Loops

Loops are a common concept in almost every programming language, but in eBPF they can be a bit more complicated. 

The goal of this task is to get familiarized with all the ways to loop in eBPF.

Try and write an eBPF program with the following loop/iterations concepts:
- For loop with `#pragma unroll` directive
- Bounded loops
- `bpf_loop` helper function
- Numeric open coded iterators that enable `bpf_for` and `bpf_repeat` helper functions
- `bpf_for_each_map_elem` Map iteration helper

For the 3. and 4. use case there are already helpers functions copied from the Linux Kernel source code for you to utilize.

## How to Run

**NOTE**: In other to be able to run this, at minimum kernel `6.4` version is needed, since this is when Numeric open coded iterators were introduced.

You can build and run the eBPF program:
```
go generate
go build
sudo ./loop
```

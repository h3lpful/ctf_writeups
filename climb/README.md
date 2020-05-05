<h1>Climb</h1>

<h3>Problem:</h3>
"Can you help me climb the rope?"

<h3>Solution:</h3>
Based on the problem, the first thing we are looking for is a buffer overflow vulnerability that can allow us to ROP.

After looking at the binary through Ghidra, we notice that main reads 500 bytes into a 32 byte variable.  
![Image of Main](https://github.com/h3lpful/ctf_writeups/blob/master/climb/images/main.PNG)

We can take a look with checksec and we get:
![image of checksec](https://github.com/h3lpful/ctf_writeups/blob/master/climb/images/checksec.PNG)

So we have no canary to worry about, and no PIE so we can hard code function addresses, and system() is already resolved for us, so there is no need to search around libc.

We can use ROPgadget > dump.txt to browse through all the available gadgets and build a ROP chain.  First, since system() requires a pointer loaded on the RDI we need to write to a memory address that we can call later.  Using vmmap with pwndbg we can see that the range 0x601000 to 0x602000 is set for both read and write.
![image of checksec](https://github.com/h3lpful/ctf_writeups/blob/master/climb/images/vmmap.PNG)

Looking in Ghidra the higher areas of that should not be used so I chose (0x601fb0).

Next we need to be able to write to that area.  Using the gadget:
0x000000000040065d : mov qword ptr \[rdx\], rax ; ret

will allow us to write from the rax to the location on the rdx.

The only thing left is to build the payload.


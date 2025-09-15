pwn_week1
=============


## 문제 분석

주어진 c코드를 보면

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main()
{
    int r1, r2, res;
    srand(time(0)); 

    for (int i = 0; i < 20; i++) {
        r1 = rand() % 10001;
        r2 = rand() % 10001;
        printf("%d. %d + %d = \n", i + 1, r1, r2);
        scanf("%d", &res);

        if (res != r1 + r2) {
            printf("Wrong answer!\n");
            return 0;
        }
    }
```

덧셈 퀴즈 프로그램으로, 20번의 덧셈 문제에 모두 정답을 입력해야 "Success! Easy~" 메시지를 볼 수 있다. 만약 오답이 나오면, 오답 메시지를 출력하고 강제 종료한다. 
따라서 프로그램 실행 시 바로 성공 메시지가 출력되려면     

1. 주소 찾기: 디버거로 Success! Easy~ 메시지가 출력되는 코드의 주소를 찾기
2. 코드 패치: "오답"일 때의 흐름에서 return 0; 부분에 해당하는 어셈블리 코드를 jmp 와 같은 명령어로 바꾸어
   Success! Easy~ 메시지 출력 함수로 바로 점프하도록 만들기

와 같은 방법을 거쳐야 한다. 

혹은 페이로드를 사용해서 간단하게 풀 수도 있는데, 공부 겸으로 두 가지 방법을 모두 사용해보겠다.


--------------------------------



## 디버거 사용

### 성공 메시지 주소 확인

disass main 해서 메인 함수를 살펴보면

<img width="762" height="85" alt="image" src="https://github.com/user-attachments/assets/36068d12-2573-4ce5-94ac-9f46184dca8b" />

이런 부분이 보인다.     
0x0000555555555313는 puts 함수를 호출하기 전에 Success! Easy~ 문자열의 주소를 
rdi 레지스터에 로드하는 명령어의 시작 주소이다. 
이 주소(0x555555555313)를 **success_addr**로 부르겠다.


### 점프할 위치 찾기

Wrong answer! 메시지를 출력하고 프로그램을 종료하는 부분을 찾아야 한다. 

<img width="910" height="142" alt="image" src="https://github.com/user-attachments/assets/f9fdff58-16a2-4168-832d-2cd2b92a0ec0" />

0x00005555555552ed에서 je 명령어가 실행되고 
덧셈 결과가 맞으면 0x555555555305로 점프하여 루프를 계속한다. 
만약 결과가 틀리면 0x00005555555552ef로 실행이 이어지고
Wrong answer! 메시지를 출력한 후 0x555555555327로 점프해서 프로그램을 종료한다.    

조작할 목표는 이 오답일 때의 흐름을 성공 흐름으로 바꾸는 것이다. 
즉 Wrong answer!를 출력하는 코드(0x00005555555552ef)를 실행하지 않도록 해야 한다.

다른 방법들도 있지만 제일 간단하게는 오답일 때의 jmp 명령어를 수정하면 된다.    

0x0000555555555303에 위치한 jmp 명령어는 프로그램을 종료하는 부분(0x555555555327)으로 점프한다.
이 jmp 명령어를 success_addr로 향하게 패치하면 된다. 
이 주소(0x0000555555555303)를 **target_addr**로 부르겠다.


## 메모리 패치

### BP 설정

<img width="660" height="266" alt="image" src="https://github.com/user-attachments/assets/d839ff7d-62f3-4131-a169-f04f46f8858f" />

target_addr 직전인 0x0000555555555303에 브레이크포인트를 설정한다. 
r을 입력하면 프로그램이 실행되고 첫 번째 덧셈 문제에서 틀린 답을 입력하면 브레이크포인트에서 멈춘다.

### 코드 패치

target_addr(0x0000555555555303)에 있는 jmp 명령어를 success_addr(0x0000555555555313)로 향하게 수정다.

* jmp 명령어의 opcode는 **0xe9**.
* 뒤따르는 4바이트는 상대 주소이다. 상대 주소는 목표 주소 - 현재 주소 - 5로 계산한다.
* 상대 주소 = 0x555555555313 - 0x555555555303 - 5 = 0x10 - 5 = 0xb

<img width="586" height="222" alt="image" src="https://github.com/user-attachments/assets/afe07cff-b2ee-470d-bcbd-382888ac1d31" />

메모리 수정하고, continue 하면 어떤 답을 입력하든 관계없이 프로그램은 Wrong answer!를 출력하는 코드를 건너뛰고, 패치된 jmp 명령어를 통해 Success! Easy~ 메시지를 출력하는 코드로 바로 이동하게 된다.


-----------------


## 페이로드 사용

### 페이로드 작성


```python
#!/usr/bin/env python3
from pwn import process
import re

p = process('./week1')
pat = re.compile(rb'(-?\d+)\s*\+\s*(-?\d+)')

for _ in range(20):
    chunk = p.recvuntil(b' = ')
    m = pat.search(chunk)
    if not m:
        chunk += p.recv(timeout=0.1)
        m = pat.search(chunk)
        if not m:
            p.close()
            raise SystemExit
    a, b = int(m.group(1)), int(m.group(2))
    p.sendline(str(a + b).encode())

p.interactive()
```

### 페이로드 주요 부분 분석 

* `pat = re.compile(rb'(-?\d+)\s*\+\s*(-?\d+)')` : 문제 문자열에서 두 정수를 추출하기 위한 정규식. 음수도 허용하고 a + b 형태를 잡아냄. rb로 바이트패턴
* `chunk = p.recvuntil(b' = ')` : " = "(문제 프롬프트 끝)를 만날 때까지 출력(바이트)을 읽음. 문제 한 줄(프롬프트 포함)을 확보하는 역할. 
* `m = pat.search(chunk)` `if not m: chunk += p.recv(timeout=0.1)`: 정규식으로 숫자 추출 시도. 실패하면 아주 짧게 추가 수신해서 다시 시도.
* `a, b = int(m.group(1)), int(m.group(2))` `p.sendline(str(a + b).encode())`: 추출한 두 수를 정수로 변환해 합을 구하고 sendline으로 답(문자열+개행)을 전송
* `p.interactive()`: 20문제를 자동으로 풀고 나서 프로세스와 직접 연결(터미널처럼 입출력), 남은 출력(Success! Easy~)을 보고 추가로 조작 가능.


### 실행 결과


<img width="703" height="121" alt="image" src="https://github.com/user-attachments/assets/870ef640-2fd3-4064-bae8-80d617e5d51f" />







```c
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>

int main() {
    char memo[8];
    char name[8];

    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    printf("name : ");
    read(0, name, 64);
    printf("hello %s\n", name);
    printf("memo : ");
    read(0, memo, 64);
    printf("memo %s\n", memo);

    return 0;
}
```


### 스택 카나리 실습 - 스택 카나리 변조

canary를 변경하는 실습이다. 

<img width="282" height="56" alt="image" src="https://github.com/user-attachments/assets/2128c7f3-0a08-4dd5-be19-7201812e938d" />

<img width="535" height="200" alt="image" src="https://github.com/user-attachments/assets/de8d6937-63c1-4a11-b666-0bfb66e15a6f" />

터미널에 'A'를 16개 입력한다.

canary와 name이 8 바이트만큼 떨어져 있으므로 'A'를 16개 입력하면 canary의 모든 바이트 값을 0x41로 덮을 수 있다.


### 스택 카나리 실습 - 스택 카나리 유출

카나리의 첫 바이트인 \x00을 다른 값으로 덮어 나머지 카나리 값(7 바이트)을 모두 알아내는 것이 목표이다.

<img width="172" height="65" alt="image" src="https://github.com/user-attachments/assets/178aece0-349d-4603-8b27-64bfe22667b4" />

canary와 name이 8 바이트만큼 떨어져 있으므로 'A'를 8개 입력하면 'A' 8개는 name에 들어가고 
기존 canary의 \x00 위치에 엔터(\n)의 아스키코드인 \x0a가 입력된다. 따라서 \x00을 제외한 나머지 카나리 값을 유출할 수 있다.


### 스택 카나리 실습 - 스택 카나리 검사 우회

위의 실습에 이어 main()의 반환 주소를 0xdeadbeef로 변조하는 것이 목표이다.

name과 memo 값을 'A'로, canary를 유출한 값으로, rbp는 임의의 값으로 덮은 후 
마지막 반환 주소를 리틀엔디언으로 0xdeadbeef가 되게 덮으면 카나리를 우회해 rip에 0xdeadbeef가 들어가게 할 수 있다.

헥스 터미널로 전환 후 아래 16진수 입력 칸에 41414141414141414141414141414141[유출한 카나리 값]0000000000000000efbeadde00000000을 입력하면 된다.





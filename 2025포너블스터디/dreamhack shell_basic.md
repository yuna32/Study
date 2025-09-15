dreamhack shell_basic
============

먼저 문제 파일 살펴보면

```c
#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <signal.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(10);
}

void banned_execve() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    exit(0);
  }
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);

  seccomp_load(ctx);
}

void main(int argc, char *argv[]) {
  char *shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);   
  void (*sc)();
  
  init();
  
  banned_execve();

  printf("shellcode: ");
  read(0, shellcode, 0x1000);

  sc = (void *)shellcode;
  sc();
}
```

추가로 flag의 위치는 "/home/shell_basic/flag_name_is_loooooong"이라는 정보도 주어졌다.

즉 open-read-write를 사용해서 flag 출력 쉘코드 작성하는 문제이다.

orw 쉘코드는 쓰기 번거로워서 좀 더 쉽게 풀려고 dreamhack 강의에서도 언급된 shellcraft 모듈을 사용하기로 했다.

https://docs.pwntools.com/en/stable/shellcraft/amd64/html 참고해서 작성했다.

------------------------------

<img width="512" height="355" alt="image" src="https://github.com/user-attachments/assets/10944a4e-2297-4ce9-878c-912645104838" />


#### 주요 코드 분석

* `flag_str = "/home/shell_basic/flag_name_is_looooong"`:  **플래그 파일의 경로**를 변수에 저장.
* `ex += shellcraft.pushstr(flag_str)`: 쉘코드를 쉽게 생성하기 위해 shellcraft 모듈 사용.
  이 줄은 `flag_str` 변수에 저장된 문자열을 스택에 push하는 쉘코드를 추가.
* `ex += shellcraft.open('rax', 0, None)`: 스택에 push된 플래그 파일 경로를 **rax 레지스터**에서 읽어와서 파일을 읽기 전용로 연다.
  0은 `O_RDONLY` (읽기 전용) 를 의미.
* `ex += shellcraft.read('rax', 'rsp', 100)`: 전 단계에서 열린 파일 디스크립터 (rax에 저장된 값)를 이용해
  파일 내용을 **100바이트**만큼 읽어와 스택 포인터 (rsp)가 가리키는 메모리 공간에 저장.
* `ex += shellcraft.write(1, 'rsp', 100)`: 파일에서 읽어온 내용을 표준 출력 (`stdout`)인 **파일 디스크립터 `1`**로 쓴다. 
  이렇게 해서 서버의 플래그 내용이 공격자의 터미널로 전송된다.
* `ex += shellcraft.exit()`: 프로세스를 종료.
* `r.sendline(asm(ex))`: `asm` 함수를 사용해 위에서 작성된 쉘코드 (ex)를 **어셈블리어**로 변환하고 한 줄로 서버에 전송.

---------------------------


<img width="717" height="162" alt="image" src="https://github.com/user-attachments/assets/4243a68f-69ef-4199-bc1a-dbf845f0bfb3" />


이렇게 플래그를 얻어낼 수 있다.

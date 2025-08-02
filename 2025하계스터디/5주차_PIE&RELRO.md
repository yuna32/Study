5주차 PIE & RELRO
=============

## 1. PIC와 PIE
### PIC

PIC는 **Position-Independent Code** 를 의미한다. 
코드가 메모리의 어느 위치에 로드되더라도 정상적으로 실행될 수 있도록 만들어진 코드이다.   

리눅스 ELF 파일은 실행파일(Executable)과 공유 오브젝트(Shared Object, so)로 2가지가 존재한다. 
이 중 공유 오브젝트는 재배치(relocation)가 가능한데, 이런 성질을 가진 코드를 PIC라고 하는 것이다.  


```c
#include <stdio.h>
char *data = "Hello World!";
int main() {
  printf("%s", data);
  return 0;
}
```

PIC가 적용된 바이너리와 그렇지 않은 바이너리를 비교해보며 알아본다.   

<img width="856" height="321" alt="image" src="https://github.com/user-attachments/assets/50bc2b77-61e3-426e-a2ad-3b462c18447e" />

<img width="295" height="62" alt="image" src="https://github.com/user-attachments/assets/ea22042b-a21e-4712-9e5d-ee72b849ab73" />

no_pic을 보면 0x402011이라는 절대 주소로 문자열을 참조하고 있다는 것을 알 수 있다.   

<img width="1105" height="347" alt="image" src="https://github.com/user-attachments/assets/ea227955-54ff-49b8-89f3-3da95ff04493" />

<img width="262" height="67" alt="image" src="https://github.com/user-attachments/assets/bff55896-5697-4859-9008-51809dd1e955" />

pic을 보면 문자열의 주소(rip+0xeaf)로 참조하고 있다는 것을 알 수 있다.

no_pic은 매핑되는 바이너리의 주소가 바뀌면 0x402011의 데이터도 같이 이동하기 때문에 제대로 실행되지 않는다.    
반면 pic의 경우 rip를 기준으로 데이터를 상대 참조하기 때문에 바이너리 매핑 주소가 바뀌어도 제대로 실행된다.


### PIE

PIE는 **Position-Independent Executable** 을 의미한다.

PIE는 실행 파일 자체를 PIC(Position-Independent Code)로 만들어
실행될 때마다 실행 파일의 메모리 주소도 무작위로 바뀌도록 한다.
PIE가 적용된 실행 파일은 ASLR과 함께 작동하여 실행 파일의 코드 영역까지 주소를 랜덤화하는 효과를 준다.   


### PIE on ASLR


```c
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    char buf_stack[0x10];                   // 스택 영역의 버퍼
    char *buf_heap = (char *)malloc(0x10);  // 힙 영역의 버퍼

    printf("buf_stack addr: %p\n", buf_stack);
    printf("buf_heap addr: %p\n", buf_heap);
    printf("libc_base addr: %p\n",
        *(void **)dlopen("libc.so.6", RTLD_LAZY));  // 라이브러리 영역 주소

    printf("printf addr: %p\n",
        dlsym(dlopen("libc.so.6", RTLD_LAZY),
        "printf"));  // 라이브러리 영역의 함수 주소
    printf("main addr: %p\n", main);  // 코드 영역의 함수 주소
}
```


위 코드를 컴파일해서 알아본다.

<img width="502" height="417" alt="image" src="https://github.com/user-attachments/assets/8059795c-485c-420e-a1dd-771b5557bffe" />

PIE가 적용되어 매 실행마다 main의 주소가 바뀌는 것을 확인할 수 있다.


### PIE 우회

* **코드 베이스 구하기:** 공유 라이브러리의 주소를 먼저 알아낸 후
  그 주소와 코드 영역 주소의 오프셋을 계산하여 코드 베이스 주소를 알아내는 방법이다.
* **Partial Overwrite (부분 덮어쓰기):** 코드 베이스를 완전히 알기 어려운 경우
   주소의 일부만 예측하여 덮어쓰는 기법이다.
    * ASLR의 특성상 코드 영역의 상위 12비트 같은 일부 주소는 고정될 수 있다.
    * 만약 공격하려는 코드의 주소와 반환 주소의 하위 바이트만 다르다면
       하위 바이트만 덮어쓰는 방식으로 원하는 코드를 실행시킬 수 있다.
    * 만약 두 바이트 이상 덮어써야 한다면
       ASLR의 무작위성을 뚫기 위해 더 많은 시도(브루트포싱)가 필요해 성공 확률이 낮아진다.


### QUIZ

##### Q1 . Shared Object는 실행할 수 있다.

A1. O

##### Q2. 다음은 file 명령어로 바이너리를 확인한 모습이다. PIE가 적용된 바이너리는 무엇인가?

1. /bin/ls: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=96b5dec8ab42c48cec65f2ba3a3e0b133869b42a, for GNU/Linux 3.2.0, stripped

2. /bin/ls: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2f15ad836be3339dec0e2e6a3c637e08e48aacbd, for GNU/Linux 3.2.0, stripped

A2. 2

##### Q3. ASLR을 꺼도 PIE가 적용된 프로세스는 무작위 주소에 매핑된다.

A3. X



## 2. RELRO

### RELRO란 

* Lazy Binding: 함수가 처음 호출될 때 GOT 테이블을 업데이트하는 방식이다.
  이 과정에서 GOT에 쓰기 권한이 필요해 공격에 취약해질 수 있다.
* `.init_array`와 `.fini_array`: 프로세스 시작 및 종료 시 실행될 함수의 주소를 저장하는 영역이다.
  공격자가 이 영역의 값을 조작하면 프로세스의 실행 흐름을 바꿀 수 있다.
* RELRO (ReLocation Read-Only): GOT, `.init_array` 등 쓰기 권한이 필요 없는 데이터 영역에 쓰기 권한을
  제거하여 보안을 강화하는 기술이다.
  * Partial RELRO: 필요한 부분에만 RELRO를 적용한다.
  * Full RELRO: 더 넓은 영역에 RELRO를 적용한다.


 ### Partial RELRO

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
  FILE *fp;
  char ch;
  fp = fopen("/proc/self/maps", "r");
  while (1) {
    ch = fgetc(fp);
    if (ch == EOF) break;
    putchar(ch);
  }
  return 0;
}
```

위 코드를 컴파일해서 자세히 알아본다.

<img width="1455" height="581" alt="image" src="https://github.com/user-attachments/assets/ab4040a8-b447-4800-a886-8e3cbc97b414" />

prelro를 실행해보면 0x404000부터 0x405000까지 쓰기권한이 있는 것을 확인할 수 있다.

<img width="1065" height="565" alt="image" src="https://github.com/user-attachments/assets/10a5f19e-3545-44af-a8cc-b6af6111442a" />

<img width="972" height="386" alt="image" src="https://github.com/user-attachments/assets/2ae0a0d3-ee41-4068-ad17-815ef19fb1fc" />

objdump를 이용해 해당 영역의 섹션 헤더를 보면 0x404000-0x405000에는 .got.plt, .data, .bss가 할당되어 있다. 
이 섹션에는 쓰기가 가능하다는 의미이다.   
하지만 .init_array와 .fini_array는 0x403e10과 0x403e18에 할당되어 있더. 쓰기 권한이 없는 영역에 존재하는 것이다.


### Full RELRO

<img width="1437" height="558" alt="image" src="https://github.com/user-attachments/assets/c7ae8ba8-217c-4145-9d14-67a1b4116cac" />

옵션을 제거해서 다시 컴파일한다.

<img width="1002" height="337" alt="image" src="https://github.com/user-attachments/assets/f5c494a3-cbe0-4cdd-90e4-66ff435e8cdf" />

data와 bss에만 쓰기 권한이 있는 것을 확인할 수 있다. 

Full RELRO가 적용되면 라이브러리 함수의 주소가 바이너리의 로딩 시점에 모두 바인딩 되기 때문에, got에 쓰기권한이 부여되지 않아 GOT Overwrite 가 불가능하다.



### RERLO 우회 

Full RELRO가 적용된 경우 쓰기 권한이 제거된 .got 영역 대신 쓰기 가능한 다른 영역을 찾아야 한다.

**Hook Overwrite**는 라이브러리 내부에 존재하는 hook 변수를 덮어쓰는 공격 기법이다.   


```
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;
  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook); // read hook
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0)); // call hook
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);
  // ...
```

위 코드에서 malloc 함수는 실행 시 __malloc_hook 변수가 존재하는지 확인하고
존재하면 해당 변수가 가리키는 함수를 호출한다.   

 __malloc_hook 변수는 쓰기 가능한 영역에 위치하므로
 공격자는 이 변수가 가리키는 주소를 조작하여 malloc이 호출될 때 원하는 코드가 실행되도록 할 수 있다.


 ### QUIZ

##### Q1. RELRO는 RELocation Read-Only의 줄임말이다.

A1. O

##### Q2. Partial RELRO에서는 .fini_array를 조작하여 실행 흐름을 조작할 수 있다.

A2. X

##### Q3. Full RELRO에서는 .got 영역을 조작하여 실행 흐름을 조작할 수 있다.

A3. X

##### Q4. No RELRO는 어떠한 RELRO 보호기법도 적용되지 않는 상태를 의미한다.

A4. O


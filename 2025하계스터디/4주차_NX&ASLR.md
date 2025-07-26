NX & ASLR 문서화
===============

## 1. NX란

### 공격자가 셸코드를 실행할 수 있는 조건

특정 프로그램에서 셸코드를 실행할 수 있으려면 다음 세 가지 조건이 충족되어야 한다.

1.  어떤 버퍼에서 스택 버퍼 오버플로우 취약점이 발생하여 이를 악용해 반환 주소를 조작할 수 있어야 한다.
2.  해당 버퍼의 주소를 알 수 있어야 한다. (버퍼에 입력한 셸코드를 쉽게 활용)
3.  해당 버퍼가 실행 가능한 메모리 영역에 있어야 한다.

### 보호 기법

이러한 세 가지 조건을 막기 위해 다음과 같은 보호 기법들이 도입되었다.

1.  **스택 카나리 (Stack Canary):** 반환 주소 조작을 어렵게 만들고 버퍼 오버플로우를 탐지하기 위해 도입되었다.
2.  **ASLR (Address Space Layout Randomization):** 메모리 주소 예측을 어렵게 만든다.
   메모리에 임의의 주소를 할당하여 공격자가 예측하기 어렵게 한다.
4.  **NX (No-eXecute):** 셸코드 실행을 막는다.

    * **개념:** 실행되는 메모리 영역과 쓰기(write)가 가능한 메모리 영역을 분리하는 보호 기법이다.
    * **목적:** 특정 메모리 영역에 쓰기 권한이 있더라도 실행 권한은 없게 해서
       스택 등에 입력된 셸코드가 실행되는 것을 방지한다.
    * **동작 방식:** CPU가 NX를 지원하며 컴파일러 옵션을 통해 바이너리에 NX를 적용할 수 있다.
      NX가 적용된 바이너리는 실행될 때 각 메모리 영역에 필요한 권한만을 부여받는다.
    * **확인 방법:** gdb나 vmmmap을 통해 NX 적용 전후의 메모리 맵을 비교하면
       NX가 적용된 바이너리는 코드 영역 외에는 실행 권한이 없음을 확인할 수 있다.
    반면, NX가 적용되지 않은 바이너리는 스택 영역([stack])에 `rwx` (읽기, 쓰기, 실행)
권한이 존재하는 것을 확인할 수 있다.

#### NX가 적용된X & ASLR 문서화
===============

## 1. NX란

### 공격자가 셸코드를 실행할 수 있는 조건

특정 프로그램에서 셸코드를 실행할 수 있으려면 다음 세 가지 조건이 충족되어야 한다.

1.  어떤 버퍼에서 스택 버퍼 오버플로우 취약점이 발생하여 이를 악용해 반환 주소를 조작할 수 있어야 한다.
2.  해당 버퍼의 주소를 알 수 있어야 한다. (버퍼에 입력한 셸코드를 쉽게 활용)
3.  해당 버퍼가 실행 가능한 메모리 영역에 있어야 한다.

### 보호 기법

이러한 세 가지 조건을 막기 위해 다음과 같은 보호 기법들이 도입되었다.

1.  **스택 카나리 (Stack Canary):** 반환 주소 조작을 어렵게 만들고 버퍼 오버플로우를 탐지하기 위해 도입되었다.
2.  **ASLR (Address Space Layout Randomization):** 메모리 주소 예측을 어렵게 만든다.
   메모리에 임의의 주소를 할당하여 공격자가 예측하기 어렵게 한다.
4.  **NX (No-eXecute):** 셸코드 실행을 막는다.

    * **개념:** 실행되는 메모리 영역과 쓰기(write)가 가능한 메모리 영역을 분리하는 보호 기법이다.
    * **목적:** 특정 메모리 영역에 쓰기 권한이 있더라도 실행 권한은 없게 해서
       스택 등에 입력된 셸코드가 실행되는 것을 방지한다.
    * **동작 방식:** CPU가 NX를 지원하며 컴파일러 옵션을 통해 바이너리에 NX를 적용할 수 있다.
      NX가 적용된 바이너리는 실행될 때 각 메모리 영역에 필요한 권한만을 부여받는다.
    * **확인 방법:** gdb나 vmmmap을 통해 NX 적용 전후의 메모리 맵을 비교하면
       NX가 적용된 바이너리는 코드 영역 외에는 실행 권한이 없음을 확인할 수 있다.
    반면, NX가 적용되지 않은 바이너리는 스택 영역([stack])에 `rwx` (읽기, 쓰기, 실행)
권한이 존재하는 것을 확인할 수 있다.

#### NX가 적용된 바이너리

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
          0x400000           0x401000 r--p     1000      0 /home/dreamhack/nx
          0x401000           0x402000 r-xp     1000   1000 /home/dreamhack/nx
          0x402000           0x403000 r--p     1000   2000 /home/dreamhack/nx
          0x403000           0x404000 r--p     1000   2000 /home/dreamhack/nx
          0x404000           0x405000 rw-p     1000   3000 /home/dreamhack/nx
    0x7ffff7d7f000     0x7ffff7d82000 rw-p     3000      0 [anon_7ffff7d7f]
    0x7ffff7d82000     0x7ffff7daa000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7daa000     0x7ffff7f3f000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f3f000     0x7ffff7f97000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f97000     0x7ffff7f9b000 r--p     4000 214000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9b000     0x7ffff7f9d000 rw-p     2000 218000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9d000     0x7ffff7faa000 rw-p     d000      0 [anon_7ffff7f9d]
    0x7ffff7fbb000     0x7ffff7fbd000 rw-p     2000      0 [anon_7ffff7fbb]
    0x7ffff7fbd000     0x7ffff7fc1000 r--p     4000      0 [vvar]
    0x7ffff7fc1000     0x7ffff7fc3000 r-xp     2000      0 [vdso]
    0x7ffff7fc3000     0x7ffff7fc5000 r--p     2000      0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc5000     0x7ffff7fef000 r-xp    2a000   2000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fef000     0x7ffff7ffa000 r--p     b000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000  39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```


#### NX가 적용되지 않은 바이너리

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
          0x400000           0x401000 r--p     1000      0 /home/dreamhack/nx_disabled
          0x401000           0x402000 r-xp     1000   1000 /home/dreamhack/nx_disabled
          0x402000           0x403000 r--p     1000   2000 /home/dreamhack/nx_disabled
          0x403000           0x404000 r--p     1000   2000 /home/dreamhack/nx_disabled
          0x404000           0x405000 rw-p     1000   3000 /home/dreamhack/nx_disabled
    0x7ffff7d7f000     0x7ffff7d82000 rw-p     3000      0 [anon_7ffff7d7f]
    0x7ffff7d82000     0x7ffff7daa000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7daa000     0x7ffff7f3f000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f3f000     0x7ffff7f97000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f97000     0x7ffff7f9b000 r--p     4000 214000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9b000     0x7ffff7f9d000 rw-p     2000 218000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9d000     0x7ffff7faa000 rw-p     d000      0 [anon_7ffff7f9d]
    0x7ffff7fbb000     0x7ffff7fbd000 rw-p     2000      0 [anon_7ffff7fbb]
    0x7ffff7fbd000     0x7ffff7fc1000 r--p     4000      0 [vvar]
    0x7ffff7fc1000     0x7ffff7fc3000 r-xp     2000      0 [vdso]
    0x7ffff7fc3000     0x7ffff7fc5000 r--p     2000      0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc5000     0x7ffff7fef000 r-xp    2a000   2000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fef000     0x7ffff7ffa000 r--p     b000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000  39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffffffde000     0x7ffffffff000 rwxp    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```



## 2. ASLR이란

Address Space Layout Randomization (ASLR)은 바이너리가 실행될 때마다 스택, 힙, 공유 라이브러리 등을 임의의 주소에 할당하는 보호 기법이다.

r2s.c를 작성해서 ASLR를 테스트해본다.

```c
#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[0x50];

  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n",
         (char*)__builtin_frame_address(0) - buf);

  printf("[1] Leak the canary\n");
  printf("Input: ");
  fflush(stdout);

  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);

  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);

  return 0;
}
```

<img width="562" height="343" alt="image" src="https://github.com/user-attachments/assets/5d065d43-acf6-4570-9f8a-ad9470f43139" />

r2s 프로그램을 여러번 실행해보면 buf의 주소가 16진수 형태로 매 실행마다 다른 값이 나오는 것을 확인할 수 있다.

위와 같은 결과가 나오는 이유는 리눅스 시스템에 ASLR이 적용되어 있기 때문에 buf라는 변수가 매 실행마다 무작위한 주소에 위치하기 때문이다.

<img width="851" height="53" alt="image" src="https://github.com/user-attachments/assets/15075167-f138-4b86-bc76-faf5d40cad99" />

ASLR은 커널에서 지원하는 보호 기법이며 /proc/sys/kernel/randomize_va_space로 출력한 값으로 확인할 수 있다.   

리눅스에서 값은 0, 1, 2의 값을 가질 수 있다. 각 ASLR이 적용되는 메모리 영역은
* No ASLR(0): ASLR을 적용하지 않음
* Conservative Randomization (1): 스택, 라이브러리, vdso 등
* Conservative Randomization + brk (2): (1)의 영역과 brk로 할당한 영역


### ASLR의 특징

```c
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  char buf_stack[0x10];                   // 스택 버퍼
  char *buf_heap = (char *)malloc(0x10);  // 힙 버퍼

  printf("buf_stack addr: %p\n", buf_stack);
  printf("buf_heap addr: %p\n", buf_heap);
  printf("libc_base addr: %p\n",
         *(void **)dlopen("libc.so.6", RTLD_LAZY));  // 라이브러리 주소

  printf("printf addr: %p\n",
         dlsym(dlopen("libc.so.6", RTLD_LAZY),
               "printf"));  // 라이브러리 함수의 주소
  printf("main addr: %p\n", main);  // 코드 영역의 함수 주소
}
```

이 코드를 컴파일해서 ASLR의 특징을 살펴볼 수 있다.

<img width="900" height="446" alt="image" src="https://github.com/user-attachments/assets/e720e842-dc20-4a91-b070-6cec918458fd" />

스택 영역의 buf_stack, 힙 영역의 buf_heap, 라이브러리 함수 printf, 코드 영역의 함수 main, 그리고 라이브러리 매핑 주소 libc_base가 출력된다.
이를 통해 알아볼 수 있는 특징은

* 코드 영역의 main 함수를 제외한 다른 영역의 주소들은 실행될 때마다 변경된다.
  실행할 때마다 주소가 변경되기 때문에 바이너리를 **실행하기 전에 해당 영역들의 주소를 예측할 수 없다.**
* 바이너리를 반복해서 실행해도 libc_base 주소 하위 12비트 값과 printf 주소 하위 12비트 값은 변겯되지 않는다.
리눅스는 ASLR이 적용되었을 때 파일을 페이지 단위로 임의 주소에 매핑한다. 따라서 페이지의 크기인 12비트 이하로는 주소가 변경되지 않는다.
* libc_base와 printf의 주소 차이는 항상 같다. ASLR이 적용되면 라이브러리는 임의 주소에 매핑된다.
그러나 라이브러리 파일을 그대로 매핑하는 것이므로 매핑한 주소로부터 라이브러리의 다른 심볼들까지의 거리(오프셋)은 항상 같다.


## 3. 라이브러리

### 라이브러리의 개념

* 라이브러리(Library)는 컴퓨터 시스템에서 프로그램들이 함수나 변수를 공유해서 사용할 수
  있도록 하는 기능이다.
* 대부분의 프로그램에서 서로 공통으로 사용하는 함수들이 많기 때문에
   C언어를 비롯한 많은 컴파일 언어들은 자주 사용되는 함수들의 정의를 묶어서
  하나의 라이브러리 파일로 만들고 이를 여러 프로그램이 공유하여 사용할 수 있도록 지원한다.
* 라이브러리를 사용하면 같은 함수를 반복적으로 정의할
  필요가 없어져 코드 개발의 효율이 높아지는 장점이 있다.
* 각 언어에서 범용적으로 많이 사용되는 함수들은 표준
 라이브러리로 제작되어 개발자들이 쉽게 해당 함수들을 사용할 수 있다.
예를 들어 C언어의 표준 라이브러리인 `libc`는 우분투에 기본으로 탑재되어 있으며
 `printf`와 같은 함수는 `libc`에 이미 정의되어 있어 별도로 정의하지 않아도
사용할 수 있다.


## 4. 링크

링크는 많은 프로그래밍 단계에서 컴파일의 마지막 단계이다. 프로그램에서 어떤 라이브러리의 함수를 사용한다면 
호출된 함수와 실제 라이브러리의 함수가 링크 과정에서 연결된다.

```c
#include <stdio.h>

int main() {
  puts("Hello, world!");
  return 0;
}
```

이 코드를 예시로 좀 더 자세히 살펴본다.

<img width="867" height="92" alt="image" src="https://github.com/user-attachments/assets/70ff2671-4c23-4dff-9856-7b82cefefbf1" />

리눅스에서 c소스코드는 전처리, 컴파일, 어셈블 과정을 거쳐 elf 형식을 갖춘 오브젝트 파일로 번역된다. 
예시에서는 `gcc -c hello-world.c -o hello-world.o` 를 이용해 어셈블했다.   

오브젝트 파일은 실행 가능한 형식을 갖추고 있지만, 라이브러리 함수들의 정의가 어디 있는지 알지 못하므로 실행은 불가능하다.
위에서 `readelf -s hello-world.o | grep puts` 의 실행 결과를 보면 puts의 선언이 심볼로는 기록되어 있지만 심볼에 대한 자세한 내용은 기록되어 있지 않다는 사실을 확인할 수 있다.

<img width="1002" height="192" alt="image" src="https://github.com/user-attachments/assets/9dc4a3c7-a36f-4c26-bfc5-44930ac485cc" />

다시 컴파일하고 비교하면 libc에서 puts의 정의를 찾아 연결한 것을 확인할 수 있다. 


### 라이브러리와 링크의 종류

라이브러리는 크게 **동적 라이브러리(Dynamic Library)** 와 **정적 라이브러리(Static Library)** 로 구분되며 이들을 프로그램에 연결하는 방식에 따라 
**동적 링크(Dynamic Link)** 와 **정적 링크(Static Link)** 로 나뉜다.

1.  **동적 링크 (Dynamic Link)**
    * 동적 라이브러리를 프로그램에 연결하는 방식이다.
    * **동작 방식:** 동적 링크된 바이너리를 실행하면 동적
      라이브러리가 프로그램의 프로세스 메모리에 매핑된다.
      실행 중에 라이브러리의 함수를 호출하면 매핑된 라이브러리에서
      해당 함수의 주소를 찾아 함수를 실행한다.
    * **장점:** 도서관에서 원하는 책을 찾아 정보를 습득하는 과정과 유사하게
      필요할 때만 라이브러리를 메모리에 올려 사용하므로 디스크 용량을 효율적으로 사용하고,
      여러 프로그램이 동일한 라이브러리를 공유할 수 있어 메모리 사용량도 줄일 수 있다.
      라이브러리가 업데이트될 경우 해당 라이브러리를 사용하는 모든 프로그램이
      자동으로 업데이트된 기능을 사용할 수 있다는 장점도 있다.

2.  **정적 링크 (Static Link)**
    * 정적 라이브러리를 프로그램에 연결하는 방식이다.
    * **동작 방식:** 정적 링크를 하면 바이너리에 정적 라이브러리의
      필요한 모든 함수가 포함된다.
      따라서 해당 함수를 호출할 때 라이브러리를 참조하는 것이 아니라
      자신의 함수를 호출하는 것처럼 직접 호출할 수 있다.
    * **장점:** 라이브러리에서 원하는 함수를 찾지 않아도 되므로 탐색 비용이 절감된다.
      라이브러리가 프로그램 내부에 포함되어 있기 때문에 외부 라이브러리 파일에
      의존하지 않아 독립적인 실행이 가능하며, 런타임에 라이브러리를 찾지 못해 발생하는
      오류가 없다.
    * **단점:** 하나의 바이너리에 라이브러리의 복제가 여러 번 이루어지게 되어 용량이 낭비된다.
      정적 링크 시 컴파일 옵션에 따라 include 한 헤더의 함수가 모두 포함될 수도 있고
      그렇지 않을 수도 있다.



### 동적 링크 vs 정적 링크

<img width="798" height="57" alt="image" src="https://github.com/user-attachments/assets/07a1231f-048d-4c19-b306-003d96228d23" />

앞의 hello-world.c를 정적 컴파일해서 static을, 동적 컴파일해서 dynamic을 각각 생성한다.


#### 용량

<img width="755" height="80" alt="image" src="https://github.com/user-attachments/assets/76969298-49be-4e1b-ab49-2fe9d72f2f96" />

각각의 용량을 비교해보면 static이 dynamic보다 50배 가까이 더 많은 용량을 차지하는 것을 확인 가능하다.


#### 호출 방법

<img width="921" height="276" alt="image" src="https://github.com/user-attachments/assets/725a6920-8437-4397-8311-e4bdf9062b60" />

static에서는 puts가 있는 `0x404d30`을 직접 호출한다.

<img width="911" height="278" alt="image" src="https://github.com/user-attachments/assets/3243337e-c048-47f5-ada1-cd732bc5b896" />

dynamic에서는 puts의 plt 주소인 `0x401040`을 호출한다. 동적 라이브러리는 함수의 주소를 **라이브러리에서 찾아야 하기 때문이다.**


## 5. PLT & GOT 

PLT(Procedure Linkage Table)와 GOT(Global Offset Table)는 동적 링크된 라이브러리에서 
심볼(함수)의 주소를 찾을 때 사용하는 테이블이다.

#### 문제점 (Runtime Resolve의 비효율성)

1.  **초기 상태:** 바이너리가 실행되면 ASLR(Address Space Layout Randomization)에
의해 라이브러리가 임의의 주소에 매핑된다.
3.  **함수 호출 과정 (Runtime Resolve):** 이 상태에서 라이브러리의 함수를 처음 호출하면
    함수의 이름을 바탕으로 라이브러리 내에서 심볼을 탐색하고
    해당 함수의 정의를 발견하면 그 주소로 실행 흐름을 옮기게 된다.
    이 과정을 "runtime resolve"라고 한다.
5.  **비효율성:** 하지만 만약 반복적으로 호출되는 함수의 정의를 매번
   탐색해야 한다면 이는 매우 비효율적일 것이다.

#### PLT와 GOT를 사용하는 이유 (비효율성 해결)

이러한 비효율성을 해결하기 위해 ELF(Executable and Linkable Format)에서는 
**GOT(Global Offset Table)** 라는 테이블을 사용한다.

* **동작 방식:** `runtime resolve`를 통해 한 번 resolve(탐색 및 주소 확인)된
  함수의 주소를 GOT 테이블에 저장한다.
* **재호출 시:** 그리고 나중에 해당 함수를 다시 호출할 때
  GOT에 저장된 주소를 바로 꺼내서 사용한다.
  이렇게 해서 매번 심볼을 탐색하는 과정을 생략해 효율성을 높인다.






  

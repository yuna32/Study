

## 스택 버퍼 오버플로 실습 - auth overwrite

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "prob.h"

char secret_passwd[16] = {0, };

int main() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    get_random_string(secret_passwd, 15);

    int auth = 0;
    char password[16] = {0, };
    printf("Enter the password: ");
    scanf("%255s", password);

    if (!strncmp(password, secret_passwd, 15))
        auth = 1;

    if (auth == 1) {
        printf("Access granted!\n");
    } else {
        printf("Access denied...\n");
    }
}
```

제공된 코드를 보면 매번 임의로 변경되는 secret_passwd에 들어가는 문자열을 알아내야 auth를 1로 변경하여 인증을
우회할 수 있다.

메모리 상에서 password 변수 아래에 auth가 존재하며 scanf()에서 스택 버퍼 오버플로가 발생하므로 이를 이용해 auth의 값을
임의로 덮어씌울 수 있다. 

password와 auth의 거리는 12바이트이다. 따라서 password 16바이트와 빈공간 12바이트를 모두 A로 채우고 auth가 1이 되도록 입력하면 
auth를 1로 변경할 수 있다.

터미널에 AAAAAAAAAAAAAAAAAAAAAAAAAAAA(A 28개)를 입력 후 
아래쪽 16진수 입력 칸에 이어서 \x01\x00\x00\x00을 작성하여 해결할 수 있다.


## 스택 버퍼 오버플로 실습 - memory leak


```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "prob.h"

int main(void) {

    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);

    struct {
        char name[8];
        char barrier[4];
        char secret[16];
    } s;

    get_random_string(s.secret, 15);

    printf("Your name: ");
    read(0, s.name, 12);
    printf("Your name is %s.", s.name);
}
```


**read(0, s.name, 12);** 로 s.name에 12바이트 입력을 받은 후 s.name을 다시 출력한다. 
s.name의 변수는 8바이트인데 입력받는 값은 12바이트이다. 즉 s.name과 s.barrier의 값을 모두 변조할 수 있다.

스택 버퍼 오버플로우로 인해 s.name과 s.secret 사이에 문자열의 끝을 의미하는 \x00가 제거된다.
printf()에서 s.name을 출력하면 문자열의 끝을 의미하는 \x00를 만날 때까지 데이터를 출력하므로 s.secret의 내용도
출력된다.

터미널에 AAAAAAAAAAAA(A 12개) 입력하면

<img width="392" height="61" alt="image" src="https://github.com/user-attachments/assets/d456eb04-89d9-4127-8eeb-b29a2cdeae86" />



## 스택 버퍼 오버플로 실습 - change control flow


```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int you_cant_call_me(void) {
    puts("What?\n");
    puts("How did you get here?\n");
    return 0;
}

int main(void) {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    
    char buf[8];
    printf("Overwrite: ");
    read(0, buf, 0x100);
    return 0;
}
```

코드를 보면 8바이트 버퍼인 buf에 read(0, buf, 0x100)을 통해 0x100바이트만큼 입력받는다. 따라서 버퍼 오버플로우가 발생한다.

<img width="525" height="318" alt="image" src="https://github.com/user-attachments/assets/65ed9d46-f895-40a5-8d36-20d121907a3a" />

메모리 뷰를 보면 buf 아래에 sfp와 ret이 있다. ret 값을 변조해서 해결할 수 있다.

buf에 버퍼 오버플로가 발생하고 그 아래에 ret가 있기 때문에 버퍼의 크기보다 큰 입력을 
주면 해당 값을 조작할 수 니다. buf와 ret 사이의 거리는 
16 바이트이므로 16개의 A를 입력 후 0xdeadbeef의 리틀 엔디언을 입력하면 
ret의 내용을 원하는 값으로 변경할 수 있다.


<img width="832" height="117" alt="image" src="https://github.com/user-attachments/assets/800b4ad9-41a1-4585-8eb9-531e5b241f0d" />


터미널에 AAAAAAAAAAAAAAAA(A 16개)를 입력하고 16진수 입력 칸에
\xef\xbe\xad\xde\x00\x00\x00\x00을 작성한다.


---------------------------------

이제 코드에서 실행할 수 없게 막아둔 함수 you_cant_call_me()를 실행하는 실습을 진행한다.

위와 동일하게 ret을 덮으면 되는데, ret을 you_cant_call_me()의 주소 0x4001ee의 리틀엔디안으로 8 바이트만큼 입력하면 된다.

터미널에 AAAAAAAAAAAAAAAA(A 16개)를 입력하고 16진수 입력 칸에 \xef\xbe\xad\xde\x00\x00\x00\x00 넣어준다.

<img width="271" height="112" alt="image" src="https://github.com/user-attachments/assets/a3bc70a9-0e1f-4550-b353-3c0bcfeb2e1c" />






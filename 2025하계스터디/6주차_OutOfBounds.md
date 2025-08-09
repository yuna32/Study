6주차 Out Of Bounds
============

## 1. 배열

### 1. 배열의 속성
* **연속된 메모리 공간:** 배열은 메모리의 연속된 공간을 차지한다.
* **크기:** 배열이 차지하는 전체 메모리 크기는 `sizeof(array)`로 표현되며
   `요소의 개수(n)`와 `요소 자료형의 크기(sizeof(elem))`를 곱한 값, 즉 `sizeof(elem) * n`과 같다.
* **길이:** 배열이 포함하는 요소의 개수를 배열의 길이라고 한다.



### 2. 배열의 주소와 참조
* **요소의 주소:** 배열의 각 요소 주소는 배열의 시작 주소, 요소의 인덱스, 요소 자료형의 크기를 이용해 계산된다.
* **주소 계산식:** `&array[k] = array + sizeof(elem)*k`
    * `&array[k]`는 k번째 요소의 주소
    * `array`는 배열의 시작 주소
    * `sizeof(elem)`은 요소 하나의 크기
    * `k`는 요소의 인덱스

----

## 2. Out of Bounds (OOB)
* **정의:** OOB는 **인덱스(Index)** 값이 잘못되거나 배열의 길이를 벗어날 때 발생하는 오류이다.
* **발생 원인:** 프로그래머가 인덱스의 범위를 명시적으로 검사하는 코드를 작성하지 않으면,
  프로세스는 계산된 주소가 배열의 범위 안에 있는지 확인하지 않고 메모리를 참조하게 된다.
    * **인지적 실수:** 프로그래밍에서 첫 번째 요소를 0번째 인덱스로 사용해야 하는데 1번째로 착각하는 경우
    * **사소한 부호 실수:** 인덱스 계산 시 부호를 잘못 사용하는 경우
    * **컴파일러의 경계 무시:** 일부 컴파일러는 인덱스 범위를 벗어나는 접근에 대해 경고하지 않음
* **유래:** 농구와 같은 스포츠에서 필드를 벗어나는 행위인 'Out of Bounds'에서 유래했다.
* **위험성:** OOB는 **치명적인 보안 취약점**의 원인이 될 수 있다.
  공격자가 임의의 인덱스를 사용하여 배열의 경계를 벗어난 특정 메모리 영역에 접근하거나 데이터를 수정할 수 있기 때문이다.

---

## 3. OOB 예제
### Proof-of-Concept

```c
#include <stdio.h>

int main() {
  int arr[10];

  printf("In Bound: \n");
  printf("arr: %p\n", arr);
  printf("arr[0]: %p\n\n", &arr[0]);

  printf("Out of Bounds: \n");
  printf("arr[-1]: %p\n", &arr[-1]);
  printf("arr[100]: %p\n", &arr[100]);

  return 0;
}
```

이 예제를 컴파일하고 실행하면

<img width="605" height="236" alt="image" src="https://github.com/user-attachments/assets/bcc72e3c-3fae-42f2-90e1-30fb2cba5038" />

* 컴파일러는 배열의 범위를 명백히 벗어나는 -1과 100을 인덱스로 사용했음에도 아무런 경고를 띄워주지 않는다.
  즉 OOB를 방지하는 것은 전적으로 개발자의 몫이다.
* arr[0]과 arr[100]은 주소 차이가 0x7ffe8a3b75f0 - 0x7ffe8a3b7460 = 0x190,
  0x190은 16진수 값이므로 10진수로 변환하면
  1 * 16^2 + 9 * 16^1 + 0 * 16^0 = 256 + 144 + 0 = 400만큼 난다. 배열의 범위를 벗어난 인덱스를 참조해도 주소 계산식을 그대로 사용함을 확인할 수 있다.

  
### 임의 주소 읽기

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char secret[256];

int read_secret() {
  FILE *fp;

  if ((fp = fopen("secret.txt", "r")) == NULL) {
    fprintf(stderr, "`secret.txt` does not exist");
    return -1;
  }

  fgets(secret, sizeof(secret), fp);
  fclose(fp);

  return 0;
}

int main() {
  char *docs[] = {"COMPANY INFORMATION", "MEMBER LIST", "MEMBER SALARY",
                  "COMMUNITY"};
  char *secret_code = secret;
  int idx;

  // Read the secret file
  if (read_secret() != 0) {
    exit(-1);
  }

  // Exploit OOB to print the secret
  puts("What do you want to read?");
  for (int i = 0; i < 4; i++) {
    printf("%d. %s\n", i + 1, docs[i]);
  }
  printf("> ");
  scanf("%d", &idx);

  if (idx > 4) {
    printf("Detect out-of-bounds");
    exit(-1);
  }

  puts(docs[idx - 1]);
  return 0;
}
```

이 예제에서 docs와 secret_code는 모두 스택에 할당되어 있으므로 docs에 대한 OOB를 이용하면 secret_code의 값을
쉽게 읽을 수 있다.

<img width="852" height="217" alt="image" src="https://github.com/user-attachments/assets/495a805f-3034-4d1d-9dfd-084f8bfbeadd" />



### 임의 주소 쓰기

```c
#include <stdio.h>
#include <stdlib.h>

struct Student {
  long attending;
  char *name;
  long age;
};

struct Student stu[10];
int isAdmin;

int main() {
  unsigned int idx;

  // Exploit OOB to read the secret
  puts("Who is present?");
  printf("(1-10)> ");
  scanf("%u", &idx);

  stu[idx - 1].attending = 1;

  if (isAdmin) printf("Access granted.\n");
  return 0;
}
```

이 예제의 마지막 부분을 보면 idAdmin이 참인지 검사하는 부분이 있다. 코드에 OOB 취약점이 있으므로
이를 이용해서 isAdmin의 값을 조작할 수 있다.

<img width="737" height="278" alt="image" src="https://github.com/user-attachments/assets/505f5407-5313-4f7d-ac7e-ce23cffba416" />

gdb로 stu와 isAdmin의 주소를 확인해보면 isAdmin이 stu보다 240바이트 높은 주소에 있음을 알 수 있다.

<img width="506" height="91" alt="image" src="https://github.com/user-attachments/assets/a6eb805f-4bd4-41a7-8fcb-136a094f7f8a" />

이렇게 isAdmin 값을 조작할 수 있다.

-----

## Quiz

#### Q1. OOB 취약점을 방어하기 위해 [A] 위치에 들어갈 올바른 검증 코드는?

```c
#include <stdio.h>
int main() {
  int buf[0x10];
  unsigned int index;
  
  scanf("%d", &index);
  [A]
  printf("%d\n", buf[index]);
  return 0;
}
```


buf 배열은 int buf[0x10];로 선언되어 있다. 
0x10은 16진수로 16을 의미하므로 배열은 16개의 요소를 가진다. 
따라서 유효한 인덱스 범위는 0부터 15까지   

사용자로부터 입력받은 index 변수가 이 유효 범위를 벗어나지 않도록 검증하는 코드가 
[A] 위치에 들어가야 한다.

보기들을 보면

1.  `if (index < 0x10) {exit(-1);}`
    * `index`가 16보다 작으면(즉, 0부터 15까지의 유효한 범위에 있으면) 프로그램을 종료
    * 잘못된 조건

2.  `if (index > 0x10) {exit(-1);}`
    * `index`가 16보다 크면(즉, 16, 17, ...) 프로그램을 종료
    * `index`가 `0x10`과 같거나 더 작은 경우(0~15)를 처리하지 못한다.
    * 또한 `index`가 음수인 경우도 처리하지 못한다.
      `unsigned int`를 사용했으므로 음수는 입력받을 수 없지만
       `0x10`과 같거나 큰 경우를 방어하지 못한다.

3.  `if (index <= 0x10) {exit(-1);}`
    * `index`가 16보다 작거나 같으면 프로그램을 종료
    * 잘못된 조건
  

4.  `if (index >= 0x10) {exit(-1);}`
    * `index`가 16보다 크거나 같으면(즉, 16, 17, ...) 프로그램을 종료
    * 유효 범위를 벗어난 인덱스(16 이상)를 방어하는 올바른 조건
    * `unsigned int`로 선언된 `index`는 음수 값을 가질 수 없으므로
      `index < 0`에 대한 추가 검증은 필요하지 않다.

따라서 정답은 **`if (index >= 0x10) {exit(-1);}`** 

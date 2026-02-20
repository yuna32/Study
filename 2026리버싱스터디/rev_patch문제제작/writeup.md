rev_patch 라이트업
==================


## 소스 코드 분석

### A. 암호화된 데이터 (`enc_flag`)

프로그램은 22바이트 크기의 암호화된 바이트 배열을 가지고 있다. 
```c
unsigned char enc_flag[] = {
    0x30, 0x3b, 0x39, 0x3e, 0x01, 0x2d, 0x48, 0x0f, 
    0x17, 0x1e, 0xe2, 0xed, 0xe7, 0xdc, 0xdc, 0xca, 
    0xd4, 0xd8, 0xc3, 0xba, 0xf3, 0xf6
};

```

### B. 초기 키 생성 로직 (`get_init_key`)

복호화에 사용될 첫 번째 키를 생성하는 함수. 수식은 

$k = (0x11 \ll 2) \oplus 0x32$

1. `0x11` (binary `0001 0001`)을 왼쪽으로 2비트 이동시키면 `0x44` (binary `0100 0100`)
2. `0x44`와 `0x32`를 XOR 연산하면 결과값은 **`0x76`** (10진수 118)

### C. 복호화 알고리즘

코드를 분석하면 각 문자는 다음과 같은 규칙으로 복호화

$$Flag[i] = enc\_flag[i] \oplus (InitialKey + i)$$

 **인덱스가 증가함에 따라 XOR 키도 1씩 증가**하는 구조


## 풀이 과정 



### 1. Patching

프로그램은 auth_status를 확인하여 복호화 함수를 실행할지 결정 

<img width="964" height="609" alt="스크린샷 2026-02-20 232636" src="https://github.com/user-attachments/assets/a67bbb4b-45ce-464a-86de-112fbf6630ed" />


* **분석:** `cmp` 명령어 뒤에 오는 `je` (Jump if Equal) 명령어 확인
* **조작:** `je`(0x74)를 `jne`(0x75)로 패치, 인증에 실패하더라도 복호화 루틴으로 진입하게 만듦
* **효과:** 정상적인 입력값 없이도 decrypt_flag 함수에 강제 진입 성공

### 2. 가변 키 로직 관찰

복호화 함수 내부에 진입하여 루프를 추적하면 키값이 고정되어 있지 않음을 알 수 있음

<img width="520" height="75" alt="스크린샷 2026-02-20 230311" src="https://github.com/user-attachments/assets/906d689c-e098-4b13-ad78-04c17bcdff53" />


* **초기 키 확인:** get_init_key 함수가 끝난 직후 rax 레지스터를 확인하면 초기 키값 확인 가능
* **가변성 파악:** 루프를 한 바퀴 돌 때마다 xor 연산에 사용되는 레지스터 값이 `1`씩 증가하는 패턴을 확인

### 3. 페이크 키 탐지와 진짜 키 역산

<img width="1413" height="86" alt="스크린샷 2026-02-20 231653" src="https://github.com/user-attachments/assets/efb694d8-b0d7-4f9e-bd8d-2d741139adbb" />


프로그램이 계산한 초기 키가 `0x7c`일 때 결과가 깨져 나오는 것을 확인 가능   

의도된 페이크 키. 플래그의 형식을 알고 있으므로 플래그를 역산.

* **역산 과정:**
1. 플래그의 첫 글자는 반드시 **'F' (0x46)**
2. 암호화된 데이터의 첫 바이트는 **0x30**입니다.
3. 수식: $0x30 \oplus \text{Real Key} = 0x46$
4. 계산: $0x30 \oplus 0x46 = \mathbf{0x76}$

<img width="344" height="90" alt="스크린샷 2026-02-20 232907" src="https://github.com/user-attachments/assets/a95c4892-8420-466f-b69b-c2c6ddb34d1f" />


* **강제 주입:** `set $rax = 0x76` 명령어를 통해 프로그램이 가진 잘못된 키를 진짜 키로 교체

### 4. 최종 플래그 확인

키를 `0x76`으로 수정한 후 실행을 계속하면 플래그 출력


<img width="612" height="162" alt="image" src="https://github.com/user-attachments/assets/6c527067-a338-4a95-a78d-960e4260b6fa" />


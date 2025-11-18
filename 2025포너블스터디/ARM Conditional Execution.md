ARM의 Conditional Execution (조건부 실행)
=====================

ARM의 Conditional Execution (조건부 실행)은 32비트 ARM 아키텍처에서 제공하는 기능이다. 



### 1. Conditional Execution의 개념

**Conditional Execution**이란 **특정 조건을 만족할 때만 해당 명령어를 실행**하도록 만드는 기능이다.

C언어의 if 문과 비슷하다고 생각하면 된다.   
차이점은, CPU가 if를 만나면 보통 코드의 다른 부분으로 점프하지만 조건부 실행은 **점프 없이** if와 유사한 기능을 수행한다.

#### 참고: 64비트 ARM

이 기능은 64비트 모드(AArch64)에서는 대부분 제거되었다.

  * 이유: 모든 명령어에 4비트의 조건 필드를 넣는 것이 명령어 인코딩 공간을 낭비하고 현대의 복잡한 CPU 파이프라인에서는 이득보다 손해가 크다고 판단되었기 때문이다.
  * 대안: `B.cond` (조건부 분기)와 `CSEL`, `CSET`, `CCMP` 같은 몇몇 조건부 선택 명령어로 대체되었다.


### 2. 작동 원리

#### 1단계: 플래그 생성

먼저 어떤 명령어가 실행되면서 그 **결과 상태**를 플래그에 저장해야 한다.

  * **`CMP` (Compare):** 두 레지스터의 값을 뺀다. (결과는 저장 안 함)
  * **`TST` (Test):** 두 레지스터의 값에 AND 비트 연산을 수행한다. (결과는 저장 안 함)
  * **`S` 접미사:** `ADDS`, `SUBS`, `MOVS`처럼 명령어 뒤에 S가 붙으면 연산 결과와 함께 플래그도 업데이트한다.

#### 2단계: CPSR

플래그는 CPSR (Current Program Status Register, 상태 레지스터)이라는 특수 레지스터에 저장된다. 
조건부 실행에 사용되는 중요 플래그는 4가지이다.

  * **N (Negative):** 연산 결과가 음수일 때 1이 된다. (최상위 비트 MSB가 1)
  * **Z (Zero):** 연산 결과가 0일 때 1이 된다. (두 값이 CMP에서 같았을 때)
  * **C (Carry):** 연산에서 올림수가 발생했을 때 1이 된다. (예를 들어, 부호 없는 수 비교 시)
  * **V (Overflow):** 연산에서 오버플로우가 발생했을 때 1이 된다. (예를 들어, 부호 있는 수 비교 시)

#### 3단계: 조건 접미사 

이제 명령어를 실행하려면 `MOV`, `ADD` 와 같은 기본 명령어 뒤에 '조건 접미사(Condition Suffix)'를 붙인다.

  * `MOVEQ`: EQ (Equal) 조건이 만족될 때만 `MOV`를 실행해라
  * `ADDNE`: NE (Not Equal) 조건이 만족될 때만 `ADD`를 실행해라

CPU는 명령어를 실행하기 직전에 CPSR의 플래그들을 확인하고, 명령어의 조건이 현재 플래그 상태와 일치하는지 확인한다.

  * **일치하면?** 명령어 실행
  * **일치하지 않으면?** 명령어 무시. (NOP 명령어처럼)

### 3. 왜 사용하는가?

가장 큰 이유는 **파이프라인 성능 향상**이다.

CPU는 여러 명령어를 미리 불러와 처리한다 (=파이프라인).  
점프 명령어는 이 흐름을 깨뜨리고 파이프라인을 비워야 해서 성능 저하를 유발한한다.

  * **일반적인 코드 (분기 사용)**
    ```arm
    ; if (r0 == 0) { r1 = 1; }
    CMP r0, #0
    BNE skip      ; r0 != 0 이면 skip으로 점프 (파이프라인 깨짐)
    MOV r1, #1
    skip:
    ...
    ```
  * **조건부 실행 코드 (분기 없음)**
    ```arm
    ; if (r0 == 0) { r1 = 1; }
    CMP r0, #0
    MOVEQ r1, #1  ; 'EQ' 조건: Z=1일 때만 실행 (점프 없음)
    ...
    ```

짧은 if 문을 처리할 때 점프를 사용하지 않아도 되므로 **코드가 더 빠르고 효율적**이 된다.

### 4. 자주 사용되는 조건 접미사 목록 

| 접미사 | 의미 (Mnemonic) | 조건 (플래그 상태) | 설명 |
| :--- | :--- | :--- | :--- |
| **EQ** | **Eq**ual | `Z = 1` | 같다 (Zero 플래그가 1) |
| **NE** | **N**ot **E**qual | `Z = 0` | 같지 않다 (Zero 플래그가 0) |
| **CS / HS** | **C**arry **S**et / **H**igher or **S**ame | `C = 1` | 부호 없는 수 비교: $\geq$ |
| **CC / LO** | **C**arry **C**lear / **Lo**wer | `C = 0` | 부호 없는 수 비교: $<$ |
| **MI** | **Mi**nus / Negative | `N = 1` | 음수 |
| **PL** | **Pl**us / Positive or Zero | `N = 0` | 양수 또는 0 |
| **VS** | O**V**erflow **S**et | `V = 1` | 오버플로우 발생 |
| **VC** | O**V**erflow **C**lear | `V = 0` | 오버플로우 없음 |
| **HI** | **Hi**gher | `C=1` and `Z=0` | 부호 없는 수 비교: $>$ |
| **LS** | **L**ower or **S**ame | `C=0` or `Z=1` | 부호 없는 수 비교: $\leq$ |
| **GE** | **G**reater or **E**qual | `N = V` | 부호 있는 수 비교: $\geq$ |
| **LT** | **L**ess **T**han | `N != V` | 부호 있는 수 비교: $<$ |
| **GT** | **G**reater **T**han | `Z=0` and `N=V` | 부호 있는 수 비교: $>$ |
| **LE** | **L**ess or **E**qual | `Z=1` or `N!=V` | 부호 있는 수 비교: $\leq$ |
| **AL** | **Al**ways | (없음) | 항상 실행 (기본값) |

-----

##  온라인 에뮬레이터를 이용한 실습

로컬에 QEMU를 구축하는 대신 에뮬레이터 사이트를 찾아 간단한 실습을 진행했다.      
해당 사이트에서는 ARMv7만을 제공하고 있어서 ARMv5대신 v7을 사용했다. 

사용한 실습 사이트: [CPUEmulator.com (visUAL)](https://www.google.com/search?q=https://cpulator.com/cpulator.html) 

### 실습 목표

CMP 명령어의 결과에 따라 `MOVEQ`와 `MOVNE`가 조건부로 실행되는 것을 눈으로 직접 확인한다.

### 실습 코드


```ARM assembler

// --- 실습 1: r0 == r1 (EQ 조건) ---
MOV r0, #10         ;  //r0에 10을 로드
MOV r1, #10         ;  //r1에 10을 로드
CMP r0, r1          ;  //r0와 r1을 비교 (10 - 10 = 0)
                    ;  //결과가 0이므로 CPSR의 Z 플래그가 1이 된다

MOVEQ r2, #100      ;  //<실행> EQ 조건. Z=1이므로 실행된다.
MOVNE r3, #200      ;  //<무시> NE 조건. Z=0이 아니므로 무시된다.


// --- 실습 2: r0 != r1 (NE 조건) ---
MOV r0, #5          ;  //r0에 5를 로드
MOV r1, #3          ;  //r1에 3을 로드
CMP r0, r1          ;  //r0와 r1을 비교 (5 - 3 = 2)
                    ;  //결과가 0이 아니므로 CPSR의 Z 플래그가 0이 된다.

MOVEQ r4, #333      ;  //<무시> EQ 조건. Z=1이 아니므로 무시된다.
MOVNE r5, #444      ;  //<실행> NE 조건. Z=0이므로 실행된다.

// 무한 루프로 프로그램 종료
stop:
    B stop
```

### 실습 결과 확인

<img width="907" height="212" alt="image" src="https://github.com/user-attachments/assets/5c7f6684-1d04-4fb2-9444-3a0e44e4f285" />

CMP r0, r1 명령어를 실행하고, 오른쪽 레지스터 창에서 CPSR 레지스터의 'Z' 플래그는 1(체크됨)이 되었음을 확인할 수 있다.

<img width="927" height="180" alt="image" src="https://github.com/user-attachments/assets/2269a373-62f7-4038-8a4d-45ccf9e5a74a" />

 `MOVEQ r2, #100`이 실행되면 r2 레지스터가 100(16진수로 00000064) 으로 바뀐다.

<img width="915" height="206" alt="image" src="https://github.com/user-attachments/assets/ae51e61a-dd64-45c1-b083-14db20a7695e" />

`MOVNE r3, #200`은 무시되고 r3 레지스터의 값은 그대로 0에서 변하지 않는 것을 확인 가능하다. 

-------------

<img width="900" height="223" alt="image" src="https://github.com/user-attachments/assets/47b4e2cd-2626-43e8-8299-27a02e4b897e" />

두번째 실습에서는 각각 r0, r1을 5와 3으로 지정한다. 정상적으로 값이 들어갔음을 확인 가능하다. 

<img width="255" height="140" alt="image" src="https://github.com/user-attachments/assets/fbf5615f-0662-4e91-9e87-d8bff1406599" />
5-3은 0(Z)가 아닌 2이므로 두 번째 실습에서는 `Z` 플래그가 체크되지 않아야 한다. CPSR 레지스터 창을 확인하면 정상적으로 처리되었음을 (체크되지 않았음을) 확인할 수 있다.


<img width="890" height="403" alt="image" src="https://github.com/user-attachments/assets/5ec6b73e-1670-41e2-be2c-00fcc1a3f6ac" />

EQ 조건인 r4는 값이 들어가지 않은 채 0으로 남아있고, NE 조건인 r5는 정상적으로 444(16진수로 000001bc) 값이 들어갔음을 확인할 수 있다. 





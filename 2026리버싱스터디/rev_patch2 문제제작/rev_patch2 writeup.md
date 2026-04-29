# Writeup (출제자용)

## 플래그

```
FLAG{S70p_7h3_W0rld_I_W4nn4_G37_0ff_Wi7h_Y0u}
```

바이너리에는 평문으로 존재하지 않는다.  
`g_enc[]` 배열에 XOR 키 `0x55`로 인코딩되어 저장되며, `print_flag()`에서 런타임에 복호화한다.

---

## 빌드 방법 (재현)

x64 Native Tools 프롬프트 또는 Developer Command Prompt에서:

```cmd
cd C:\Users\gram\Desktop\rev4\ctf

:: x86(32-bit) Release 빌드
cmake -B build -A Win32 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

:: 결과물: build\Release\crackme.exe
```

---

## 검증 로직 요약

```
main:
    r1 = check_magic(input)      // 패치 1: JE → JNE
    r2 = check_structure(input)  // 패치 2: NOP × 2
    r3 = check_checksum(input)   // 패치 3: EAX = 1 강제
    if (r1 + r2 + r3 == 3) → print_flag()
    else → "Access Denied."
```

어느 함수가 실패했는지 개별 메시지가 없으므로, 출력만으로는 원인을 특정할 수 없다.

---

## 패치 1 — `check_magic` : JE → JNE

### 의도된 로직 (버그 삽입 전)

```
input[0] == 'S'  &&  input[3] == 'W'  &&  input[7] == 'G'
→ 세 개 모두 맞으면 return 1
```

### 실제 소스 (뒤집힌 분기)

```c
int fail_count = 0;
if ((input[0] ^ 0x53) != 0) fail_count++;
if ((input[3] ^ 0x57) != 0) fail_count++;
if ((input[7] ^ 0x47) != 0) fail_count++;

if (fail_count == 0) goto fail_label;  // 버그: == 0 이면 실패
return 1;
fail_label:
return 0;
```

### 생성 어셈블리 (x86, pragma optimize off)

```asm
; ... 더미 루프 (noise 계산) ...

cmp  dword ptr [ebp-??], 0    ; cmp fail_count, 0
je   fail_label               ; <── PATCH: 0x74 → 0x75 (JNE)
mov  eax, 1
ret
fail_label:
xor  eax, eax
ret
```

### 패치 방법

| 항목 | 값 |
|------|-----|
| 패치 크기 | 1 바이트 |
| Before | `74 XX` (`JE short rel8`) |
| After  | `75 XX` (`JNE short rel8`) |
| 위치 찾기 | `check_magic` 함수 내 세 번의 XOR 비교 직후 나타나는 `JE` |

x32dbg: 해당 `JE` 명령에서 우클릭 → **Binary Edit** → `74` → `75`

### 패치 후 통과 조건

입력의 `[0]='S'`, `[3]='W'`, `[7]='G'` 이면 `fail_count==0` → JNE 미분기 → `return 1`

---

## 패치 2 — `check_structure` : NOP × 2

### 소스

```c
int len = (int)strlen(input);

if (len != 12)      return 0;  // JNE ← NOP #1
if (input[4] != '-') return 0; // JNE ← NOP #2

return 1;
```

### 생성 어셈블리

```asm
; ... strlen 호출 ...
cmp  eax, 12
jne  ret_zero_1           ; <── NOP #1: 74 XX → 90 90

; ... input[4] 로드 ...
cmp  byte ptr [...], 2Dh  ; '-' = 0x2D
jne  ret_zero_2           ; <── NOP #2: 75 XX → 90 90

mov  eax, 1
ret
ret_zero_1:
ret_zero_2:
xor  eax, eax
ret
```

### 패치 방법

| 패치 | Before | After | 크기 |
|------|--------|-------|------|
| NOP #1 | `75 XX` or `0F 85 XX XX XX XX` | `90 90` or `90×6` | 2 or 6 바이트 |
| NOP #2 | `75 XX` or `0F 85 XX XX XX XX` | `90 90` or `90×6` | 2 or 6 바이트 |

> **주의**: 두 JNE 중 하나만 NOP하면 나머지 검사에서 여전히 0을 반환한다.  
> 반드시 두 곳 모두 처리해야 한다.

x32dbg: 각 JNE에서 우클릭 → **Binary Edit** / 또는 명령어를 `nop`으로 어셈블

### 패치 후 효과

길이·구분자 조건 모두 무시하고 곧바로 `return 1`에 도달

---

## 패치 3 — `check_checksum` : EAX 강제 1

### 소스

```c
int sum = 0;
for (int i = 0; input[i]; i++) sum += (unsigned char)input[i];

if (sum < 2) return 0;

for (int d = 2; (long long)d*d <= (long long)sum; d++)
    if (sum % d == 0) return 0;   // 합산값이 소수가 아니면 0

return 1;
```

### 왜 단순 분기 하나 뒤집기로는 안 되는가

나누기 루프 안에 `return 0` 분기가 반복적으로 나타나며, 모든 루프 분기를 패치해도
루프 종료 조건 자체가 남는다. 함수 반환값을 직접 고정하는 것이 가장 단순하다.

### 권장 패치 방법 A — 함수 진입부 덮어쓰기

함수 시작(더미 루프 전) 첫 유효 명령 위치에서:

```asm
; Before (함수 prologue 직후)
push  ebp
mov   ebp, esp
sub   esp, XX
...

; After: 진입 직후 즉시 반환
mov   eax, 1    ; B8 01 00 00 00
ret             ; C3
```

→ `B8 01 00 00 00 C3` (6바이트) 를 함수 본문 시작 위치에 써넣는다.

### 권장 패치 방법 B — 마지막 `return 1` 직전 수정

함수 말미의 `mov eax, 1 / ret` 직전에 있는 `xor eax, eax` (실패 경로)를  
`mov eax, 1` (`B8 01 00 00 00`)로 교체하면 어떤 경로로 반환해도 EAX=1.

| 패치 | Before | After |
|------|--------|-------|
| EAX 고정 | `33 C0` (`xor eax, eax`) | `B8 01 00 00 00` (`mov eax, 1`) |

> 크기 불일치(2 bytes → 5 bytes)가 발생하면 기존 2바이트 위치부터 5바이트를
> 덮어쓰고 나머지를 NOP으로 채운다. x32dbg의 어셈블 기능이 이를 자동 처리한다.

---

## 최종 테스트 입력 (패치 완료 후)

```
S12W-34G5678
```

- `[0]='S'`, `[3]='W'`, `[7]='G'` → check_magic 통과 (패치 1)
- 길이·구분자 검사 우회됨 → check_structure 통과 (패치 2)
- EAX=1 고정 → check_checksum 통과 (패치 3)

출력:
```
Correct! FLAG{S70p_7h3_W0rld_I_W4nn4_G37_0ff_Wi7h_Y0u}
```

---

## 더미 연산 위치 요약

| 함수 | 더미 코드 | 역할 |
|------|-----------|------|
| `check_magic` | `noise` 루프 (3회 반복, `*31 XOR 0x55`) | 핵심 XOR 비교 앞을 가림 |
| `check_structure` | `dummy = input[0]*7+13; dummy ^= (dummy>>3)` | strlen 호출 앞을 가림 |
| `check_checksum` | `sink` 루프 (k² 합산, 4회) | 실제 sum 루프와 혼동 유도 |

모두 반환값에 영향 없음. `(void)` 캐스트로 컴파일러 경고 억제.

---

## 난이도 설계 근거

| 패치 기법 | 학생이 알아야 할 것 |
|-----------|---------------------|
| JE → JNE | `fail_count` 카운터 로직을 읽고, "왜 성공인데 0을 반환하는가"를 추적 |
| NOP × 2 | 두 개의 독립 검사가 있음을 인지하고, 하나만 NOP했을 때 여전히 실패함을 경험 |
| EAX 강제 | 루프 내 분기가 많아 개별 패치로 해결 불가능함을 깨닫고 반환값 직접 조작으로 전환 |

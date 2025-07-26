Return Address Overwrite 라이트업
============================

<img width="347" height="525" alt="image" src="https://github.com/user-attachments/assets/d31ce2f3-19a5-44bf-a458-8a3c0b9ff726" />

제공되는 rao.c 이다.

취약점은 **scanf("%s", buf)** 에 있다. **%s를 사용했기 때문에 버퍼 오버플로우가 발생**할 수 있는 것이다.
scanf("%s", buf)와 같이 %s 포맷 스트링을 사용하는 것은 버퍼의 길이를 제한하지 않아 입력 길이에 따라 
버퍼 오버플로우를 발생시킬 수 있다. 공백 문자, 탭, 개행 문자 등이 들어올 때까지 계속 입력을 받는 
특성이 있다. 

따라서 scanf 사용 시에는 %[n]s와 같이 최대 n개의 문자만 받도록 제한해야 한다.

strcpy, strcat, sprintf와 같이 버퍼의 길이를 입력하지 않는 표준 함수들은 대부분 위험하다.
strncpy, strncat, snprintf, fgets, memcpy 등 버퍼 크기를 명시적으로 입력하는 함수들을 
사용하는 것이 바람직하다.


<img width="1320" height="147" alt="image" src="https://github.com/user-attachments/assets/89cca8a3-f8b0-4742-880b-66308a9f31b5" />

이렇게 버퍼 오버플로우를 발생시키면 Segmentation fault라는 에러가 출력된다. 이는 프로그램이 
잘못된 메모리 주소에 접근했다는 의미이며, 프로그램에 버그가 발생했다는 신호이다. 

뒤의 (core dumped)는 코어 파일을 생성했다는 것으로, 프로그램이 비정상 종료됐을 때, 디버깅을 
돕기 위해 운영체제가 생성해주는 것이다. 

나머지는

https://github.com/yuna32/Writeup/blob/main/Dreamhack%20Return%20Address%20Overwrite.pdf

(코어 파일이 제대로 찾아지지 않는다는 동일한 문제 발생) 


## 참고: C/C++ 문자열 종결자(Terminator)와 Out-Of-Bounds (OOB) 취약점

### 널 바이트(Null Byte, '\x00')의 중요성
C 계열 언어에서는 
널 바이트로 종료되는 데이터 배열을 문자열로 취급하며, 대부분의 표준 문자열 함수는 널 바이트를 
만날 때까지 연산을 진행한다. 예를 들어 strcpy는 src의 널 바이트까지 dest에 복사합니다.

### OOB(Out-Of-Bounds) 취약점 발생 원인
문자열 함수가 널 바이트를 찾을 때까지 배열을 참조하므로
만약 src에 널 바이트가 없거나 정의된 배열 크기를 넘어 계속 인덱스를 증가시키는 경우 참조하려는 
인덱스가 배열의 크기를 벗어나는 현상이 발생한다. 이를 Index-Out-Of-Bounds 또는 줄여서 OOB라고 부른다.

OOB는 해커가 의도하지 않은 주소의 데이터를 읽거나 조작할 수 있게 하여 소프트웨어에 
심각한 오작동을 일으킬 수 있는 심각한 취약점이다.

따라서 입력의 길이를 제한하는 문자열 함수를 사용하고, 
문자열을 사용할 때는 반드시 널 바이트로 종료되는지 확인해야 한다.


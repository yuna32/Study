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

FSB 



return address 덮어쓰기

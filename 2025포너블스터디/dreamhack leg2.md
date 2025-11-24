dreamhack leg2
================



undefined8 main(void)

{
  proc_init();
  vuln();
  return 0;
}



<img width="407" height="350" alt="image" src="https://github.com/user-attachments/assets/8b65dfaa-935c-44f0-b0cc-dc534f5238d4" />

* 취약점 1 (FSB): printf(name_pointer); 부분에서 사용자의 입력(name_pointer)이 포맷 스트링 인자 없이 그대로 출력 함수에 들어갑니다. 이를 통해 스택 내부의 값을 훔쳐볼(Leak) 수 있습니다.


* 취약점 2 (BOF): read_input(&v1, ...) 함수 호출 시, v1 변수(스택 버퍼)의 크기보다 훨씬 큰 값을 입력받습니다. 어셈블리어에서 mov w1, #0x200 (512 바이트)을 입력받지만, 할당된 버퍼는 0x100 (256 바이트) 수준이므로 오버플로우가 발생합니다



return address 덮어쓰기

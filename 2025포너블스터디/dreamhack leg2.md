dreamhack leg2
================



undefined8 main(void)

{
  proc_init();
  vuln();
  return 0;
}



void vuln(void)

{
  undefined1 auStack_100 [256];
  
  printf("your name > ");
  read_input(&name_pointer,0x20);
  printf("Hi! ");
  printf(&name_pointer);
  putchar(10);
  printf("Let me know your message!");
  printf("\n> ");
  read_input(auStack_100,0x200);
  return;
}




return address 덮어쓰기

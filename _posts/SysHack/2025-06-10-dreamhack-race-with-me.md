---
layout: post
title: "[Dreamhack] Race with me?"
date: 2025-06-10 10:57 +0900
category: ['Syshack']
tag: ['system', 'dreamhack', 'hacking', 'pwn', 'pwnable', '드림핵', '보안', '시스템', '시스템해킹', '포너블', '해킹']
image: /assets/img/post/race-with-me/image0.png
---

> **Dreamhack Syshack Lv.1**

## P1. 문제 분석


문제의 소스 파일을 다운 받아 분석을 시작하자.

Docker 기반의 문제일 경우 Dockerfile에 flag의 위치 정도를 나타내는 명령어가 있을 수 있다. 

Web 문제의 경우 pip lib 등의 버전을 확인할 수 있고, path traversal 기법에 활용할 수 있으니 한번쯤 훑고 지나가는 것이 좋다.

![](/assets/img/post/race-with-me/image1.png)

이 문제에선 flag의 위치와 바이너리의 위치 정도를 나타내는 것을 볼 수 있다.


![](/assets/img/post/race-with-me/image2.png)

문제 파일을 살펴보면 해당 화면이 출력된다.

![](/assets/img/post/race-with-me/image3.png)

1을 입력 시 또 다른 입력을 받는다.

![](/assets/img/post/race-with-me/image4.png)

2를 입력 시 다른 동작 없이 다시 메인 메뉴가 출력된다.

3은 flag를 얻기 위한 입력으로 보이고 4는 프로그램을 종료한다.

문제의 소스 파일에서 소스코드를 제공하지 않기 때문에 ida를 이용해 디스어셈블을 해보자.

문제의 정답인 flag를 얻기위한 기능인 3번에 대한 기능을 먼저 확인한다.
![](/assets/img/post/race-with-me/image5.png)

v3라는 변수가 3이면 qword_4030이라는 변수의 값이 3735928559와 같은지 확인한다.

조건이 맞지 않으면 `Don't have permission1!`라는 문자열을 출력을 한다.

그럼 qword_4030라는 변수의 값을 어떻게 바꿀 수 있을까?

![](/assets/img/post/race-with-me/image6.png)

1을 입력했을 때 받는 입력의 경우 qword_4038이라는 변수에 입력을 받고 있다. 그럼 2를 입력받는 경우를 살펴보자.

![](/assets/img/post/race-with-me/image7.png)

2를 입력한 경우 thread 함수를 실행시킨다.

thread 함수의 원문을 살펴보자
```c
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
```
함수 3번째 인자에 함수를 입력받는다. 이 인자는 thread 함수를 통해 실행될 함수를 매개로 한다.

그럼 `start_routine` 이라는 함수를 살펴보자.

![](/assets/img/post/race-with-me/image8.png)

qword_4038이 3735928559가 아닐 때 0xA 동안 sleep 후 qword_4030를 qword_4038의 값으로 초기화한다.

이런 경우에 qword_4038에 3735928559라는 값을 입력할 경우 thread 함수가 변수 초기화를 진행하지 않고 바로 끝나버린다.

이는 thread의 경쟁 상태로 해결할 수 있다.

경쟁 상태를 활용하면 thread가 실행 중일 때 실행에 관여하는 데이터가 변동되면 변동된 상태로 실행되게 된다.

## P2. Exploit code

```python
from pwn import *

e = ELF('./chall')
p = e.process()

# 경쟁 상태를 활용한 if문 bypass
p.sendlineafter(b'Input: ', str(2).encode())
p.sendlineafter(b'Input: ', str(1).encode())
p.sendlineafter(b'Input: ', str(3735928559).encode())

# thread routine 기다리기
sleep(0xa)

# Get flag
p.sendlineafter(b'Input: ', str(3).encode())

p.interactive()
```

![](/assets/img/post/race-with-me/image9.png)

따로 서버 요청없이 로컬에서 진행했기 때문에 Fake flag가 나왔지만 remote로 동작시키면 똑같이 동작할 것이다.

![](/assets/img/post/race-with-me/image10.png)

**clear!**

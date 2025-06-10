---
layout: post
title: "[Dreamhack] Rock Paper Scissors"
date: 2025-06-10 11:55 +0900
category: ['Syshack']
tag: ['system', 'dreamhack', 'hacking', 'pwn', 'pwnable', '드림핵', '보안', '시스템', '시스템해킹', '포너블', '해킹']
image: /assets/img/post/rock-paper-scissors/image0.png
---

> **Dreamhack Syshack Lv.1**

## P1. 문제분석

![](/assets/img/post/rock-paper-scissors/image1.png)

문제의 바이너리를 실행한 모습이다.

이번 문제에서는 소스코드도 함께 제공하기 때문에 소스코드와 함께 분석해보자.

소스 코드 원문

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(void)
{
    char c, t[4] = "RPS";
    int i, p, r;
    srand(time(NULL));
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    for(i = 1; i <= 10; i++)
    {
        printf("Round %d of 10\n", i);
        printf("Put your hand out(R, P, S): ");
        scanf("%c", &c);
        while(getchar() != '\n');
        switch(c)
        {
            case 'R':
                p = 0;
                break;
            case 'P':
                p = 1;
                break;
            case 'S':
                p = 2;
                break;
            default:
                printf("Nope!\n");
                return 0;
        }
        sleep(1);
        r = rand() % 3;
        printf("You: %c Computer: %c\n", t[p], t[r]);
        if((r - p + 1) % 3)
        {
            printf("Nope!\n");
            return 0;
        }
    }
    int fd = open("./flag", O_RDONLY);
    char flag[64] = { 0, };
    read(fd, flag, 64);
    printf("Flag is %s\n", flag);
    close(fd);
    return 0;
}
```
  
소스코드에서 입력을 받는 부분을 살펴보자.

```c
scanf("%c", &c); 			// 입력
while(getchar() != '\n'); 	// 줄바꿈 문자가 입력될 때 까지 (Enter 입력)
switch(c) 					// 입력 필터링
{
	case 'R':
		p = 0;
  		break;
  	case 'P':
  		p = 1;
  		break;
  	case 'S':
  		p = 2;
  		break;
  	default:
  		printf("Nope!\n");
  		return 0;
}
```

`switch`문을 이용한 필터링을 하고 있는 모습이다.
  
포멧 문자 `%c`를 통해 문자 1개를 받고 있기 때문에 `overflow`를 이용한 공격은 불가능해 보인다.
  
그러나, 소스코드를 확인해보면
```c
srand(time(NULL));
```

`srand()` 함수를 이용해 랜덤한 수를 생성하고 있는데 함수의 인자로 `time(NULL)`을 사용하고 있다.
  
여기서 발생하는 취약점을 알기 위해선 `srand()`의 특징을 알아야한다.
  
`srand()` 함수는 인자를 이용하여 내부 로직에 사용될 키를 설정하고 `rand()` 함수를 사용하면 내부 로직을 통해 생성된 무작위 수를 반환한다.
  
`srand()`에 사용되는 키는 사용자가 설정할 수 있지만 내부 로직은 고정이기 때문에 키를 알면 생성되는 난수를 유추할 수 있다.
  
```c
r = rand() % 3;
```

`rand()` 함수의 인자 또한 없기 때문에 생성되는 난수는 고정적으로 반환된다.
  
예제를 통해 보여주자면

### P1.1 `rand()`함수 알아보기

예제 코드

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    printf("%d\n", rand());
    printf("%d\n", rand());
    printf("%d\n", rand());
    
    return 0;
}
```

결과
  
```bash
$ ./a.out
1804289383
846930886
1681692777
$ ./a.out
1804289383
846930886
1681692777
$ ./a.out
1804289383
846930886
1681692777
```

3번을 실행한 결과에서 모두 같은 값이 나온 것을 알 수 있다.

혹시 `srand()` 함수로 난수에 대한 키를 설정을 안해줘서 그런 것이 아닐까 싶다면 아래 2번 예제를 통해 확인해보자

예제 코드

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
    srand(20000);
    printf("%d\n", rand());
    printf("%d\n", rand());
    printf("%d\n", rand());

    return 0;
}
```
  
결과

```bash
$ ./a.out
164365245
1062436714
2012788020
$ ./a.out
164365245
1062436714
2012788020
$ ./a.out
164365245
1062436714
2012788020
```
  
이로써 C언어 `rand` 함수에 대한 특징을 알아보았으니 이를 통해 공격 코드를 작성해보자
  
## P2. Exploit code

C언어의 `srand()` 함수와 `time()` 함수를 사용하여야 하기 때문에 python의 `ctypes` 라이브러리를 이용한다.

```python
from pwn import *
from ctypes import CDLL

libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')      # linux libc.so.6 C언어 라이브러리 로드
e = ELF('./deploy/chall')
p = e.process()
rsp = {0:b'R', 1:b'S', 2:b'P'}                      # 묵찌빠 정의

libc.srand(libc.time())								# srand 키 설정

for _ in range(10) :
    r_num = libc.rand() % 3							# 시스템과 같은 난수 생성
    p.sendlineafter(b'Put your hand out(R, P, S): ', rsp[2 - r_num])

p.interactive()
```

```bash
$ python3 ./ex.py
[*] './deploy/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Starting local process './deploy/chall': pid 67377
[*] Switching to interactive mode
You: S Computer: P
Flag is DH{fake_flag}
```
  

로컬에서 성공했다. 이제 문제 서버로 공격을 시도해보자.

![](/assets/img/post/rock-paper-scissors/image2.png)

혹시라도 실패시 `libc.srand(libc.time(None))` 부분의 키값에 `+1`을 하여 시간을 보정해보자.
  
  
**Clear!**
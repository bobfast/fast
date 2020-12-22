# FAST (Fileless Attack Solution Team) Project

FAST 프로젝트는 API 후킹을 통해 파일리스 공격을 탐지/차단하는 BoB 프로젝트입니다.

[Pinjectra](https://github.com/SafeBreach-Labs/pinjectra)에 수록된 각 번호별 공격에 대응하기 위해

[MS Detours 라이브러리](https://github.com/microsoft/Detours)를 사용해 API 후킹을 합니다.

# 환경 구성

1. C++/CLR Winform 사용을 위해 다음 영상과 같이 VS Extension을 설치해주어야 합니다.
    - [https://www.youtube.com/watch?v=gB51Tla5pPI](https://www.youtube.com/watch?v=gB51Tla5pPI)
        - **C++/CLR Windows Forms for Visual Studio 2019**
        - [https://www.google.com/search?q=winform+c%2B%2B+visual+studio+2019&oq=winform+c%2B%2B+&aqs=chrome.2.69i57j69i59j0i19j0i19i30j0i10i19i30j0i19i30l2j69i61.4334j0j7&sourceid=chrome&ie=UTF-8#kpvalbx=_jk-QX-LCKtDR-QaVpoaICg21](https://www.google.com/search?q=winform+c%2B%2B+visual+studio+2019&oq=winform+c%2B%2B+&aqs=chrome.2.69i57j69i59j0i19j0i19i30j0i10i19i30j0i19i30l2j69i61.4334j0j7&sourceid=chrome&ie=UTF-8#kpvalbx=_jk-QX-LCKtDR-QaVpoaICg21)
        - Visual Studio 2019 기반

2. **Visual Studio Installer**에서 `C++를 사용한 데스크톱 개발`, `.NET 데스크톱 개발` 개별 구성 요소를 포함시켜야 합니다.

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
        - `dllmain.cpp` : 후킹 함수 및 detours library로 후킹하는 DllMain 구현부
        - `framework.h` : dll 헤더 파일

- fast-attack_tool
    - InjecteeDLL
        - `ReflectiveLoader.h` : Reflective Loader 헤더 파일
        - `InjecteeDLL.cpp` : 메시지 박스를 띄우는 기능의 DllMain 구현부
        - `ReflectiveLoader.cpp` : Reflective Loader 함수부
    - fast-attack_tool
        - `CppCLR_WinformsProjekt.cpp` : Winform을 Run하는 기능
        - `gen_payload.cpp` : Shellcode 생성 함수
        - `LoadLibraryR.h` : 공격 방식별 함수 헤더 파일
        - `Form1.h` : Winform 구현부
        - `LoadLibraryR.cpp` : 공격 방식별 함수 구현부
        - `Form1.cpp` : init(), attack() 함수 구현부

# 사용법

## fast-monitor

1. fast-monitor 디렉토리 안의 솔루션 빌드하여 fast-monitor.exe 와 FAST-DLL.dll을 생성.
2. fast-monitor.exe 실행
    - fast-monitor.exe와 FAST-DLL.dll이 같은 경로 안에 있어야 함
    - Start : 글로벌 후킹(아직 모든 프로세스 후킹 안됨.)
    - Stop : 글로벌 후킹 언훅.
3. Start 버튼을 눌러 글로벌 후킹하여 모니터링 시작.
    - 공격이 탐지되어 차단되면 모니터에서 공격 차단을 알리는 메시지 박스가 띄워진다.

## fast-attack_tool

1. fast-attack_tool 디렉토리 안의 솔루션 빌드하여 fast-attack_tool.exe 와 InjecteeDLL.dll을 생성.
2. fast-attack_tool.exe를 실행
    - fast-attack_tool.exe와 InjecteeDLL.dll이 같은 경로 안에 있어야 함

    - Target PID : 타겟 프로세스 PID 입력
        - Target PID를 입력하지 않거나 0을 입력 시 TestProcess 또는 notepad를 생성해서 공격을 수행 가능
    - Target TID : 타겟 스레드 TID 입력(공격에 따라 사용하지 않는 입력)
    - Option : 공격 방식 선택
        - #1 : CreateRemoteThread(VirtualAllocEx, WriteProcessMemory)
        - #2 : CreateRemoteThread(CreateFileMappingA, MapViewOfFile, NtMapViewOfSection)
        - ~~#3 : AtomBombing(QueueUserAPC, GlobalAddAtomA, GlobalGetAtomNameA, NtQueueApcThread)~~ → 작동 안함
        - #4 : ThreadHijacking(SuspendThread, SetThreadContext, ResumeThread, VirtualAllocEx)
        - #5 : SetWindowLongPtrA(SetWindowLongPtrA, VirtualAllocEx, WriteProcessMemory)
        - #6 : CtrlInject(SendInput, PostMessageA, VirtualAllocEx, WriteProcessMemory)
        - #7 : PROPagate(SetPropA, VirtualAllocEx, WriteProcessMemory)
        - #8 : CreateRemoteThread(VirtualAllocEx, VirtualProtectEx, WriteProcessMemory)
    - Radio Button : Reflective DLL Injection과 Shellcode Injection 중 payload를 선택
    - Attack : 공격 실행
3. Attack 버튼을 눌러 공격을 실행하여 성공하면 타겟 프로세스에서 공격 성공을 나타내는 메시지 박스가 띄워진다.

---

## 설치 방법

## FAST Monitor/DLL

1. fast-setup.exe 실행하여 설치
2. Volatility 모듈을 설치하려는 경우 fast-volatility3-plugin.exe 실행
3. Ghidra 연동, Cuckoo Sandbox 연동 기능을 사용하려면 환경을 따로 구축하고 모니터 메뉴에서 설정을 적용해야 함


## FAST Web Report

1. 환경 구성
    - 아파치 설치 : [https://www.apachelounge.com/download/](https://www.apachelounge.com/download/)
    - PHP 설치 : [https://windows.php.net/download/](https://windows.php.net/download/)
    - mysql 설치 : [https://dev.mysql.com/downloads/mysql/](https://dev.mysql.com/downloads/mysql/)
    - APM 웹 서버를 [localhost](http://localhost) 주소로 구동한다.

2. fast-web-report 디렉토리 안의 htdocs를 아파치 설치 경로 안에 덮어씌운다.

- htdocs/config.json 안의 설정을 변경한다.
    - "dump" : "(dump파일 경로)"
        - Installer로 설치 시 'C:\Users\(유저 이름)\Documents\FAST Detection Results\'
    - "cuckoo" :  "(cuckoo web server 주소)"
        - e.g. "cuckoo": "[http://192.168.0.10:8000/](http://192.168.0.10:8000/)"

3.  db 구성

- 구축한 웹 서버의 다음 웹 페이지에 접속
    - (APM 서버주소)/dbinit.php
    - (APM 서버주소)/dbinit_fast.php



## FAST Cuckoo Sandbox Plugin

1. Cuckoo Sandbox 2.0.7 설치 및 구동
2. /usr/local/lib/python2.7/dist-packages/cuckoo 경로에서 fast_cuckoo.patch로 patch
3. cuckoo sandbox 설치 시 생성되는 .cuckoo 디렉토리 경로인 CWD(Cuckoo Working Directory)에서  fast_cwd.patch로 patch
4. .cuckoo/analyzer/windows/ 경로 안에 fast-background.exe 다운로드
5. .cuckoo/monitor/(lastest 버전 디렉토리)/ 경로 안에 FAST-DLL.dll, InjDll64.exe 다운로드

# FAST (Fileless Attack Solution Team) Hooking Project

FAST 프로젝트는 API 후킹을 통해 파일리스 공격을 탐지/차단하는 BoB 프로젝트입니다.

[Pinjectra](https://github.com/SafeBreach-Labs/pinjectra)에 수록된 각 번호별 공격에 대응하기 위해

[MS Detours 라이브러리](https://github.com/microsoft/Detours)를 사용해 API 후킹을 합니다.

## 파일 및 디렉터리 구성

+ FAST-Reflective-DLL-Injection: 별도의 함수(LoadLibraryR)를 직접 구현하여 공격하는 Reflective DLL 공격 프로그램 (참고 프로젝트: [stephenfewer / ReflectiveDLLInjection](https://github.com/stephenfewer/ReflectiveDLLInjection))
+ CreationHook: Pinjectra #2 (OpenProcess_VirtualAllocEx_WriteProcessMemory(\"MsgBoxOnProcessAttach.dll\") \[Entry: LoadLibraryA\]) 기법에 대응하는 API Hooking 솔루션
+ NtAddAtomEx+JS
+ Rua-A: Pinjectra #4
+ Silver0Hook: Pinjectra #3 (CreateFileMappingA_MapViewOfFile_OpenProcess_PNtMapViewOfSection)
+ kmkmi #6 #10
+ Microsoft Detours 프로젝트
  + include
  + samples
  + src
  + vc
  + Makefile

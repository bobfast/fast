#pragma once
#include "Form1.h"
using namespace CppCLRWinformsProjekt;

#define MSG_SIZE 256

void CallVirtualAllocEx(LPVOID monMMF);
void CallQueueUserAPC(LPVOID monMMF);
void CallWriteProcessMemory(LPVOID monMMF);
void CallCreateRemoteThread(LPVOID monMMF);
void CallNtMapViewOfSection(LPVOID monMMF);
void CallCreateFileMappingA(LPVOID monMMF);
void CallGetThreadContext(LPVOID monMMF);
void CallSetThreadContext(LPVOID monMMF);
void CallNtQueueApcThread(LPVOID monMMF);
void CallSetWindowLongPtrA(LPVOID monMMF);
void CallSleepEx(LPVOID monMMF);

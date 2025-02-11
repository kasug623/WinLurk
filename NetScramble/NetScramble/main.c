#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include "main.h"

#pragma comment(lib, "iphlpapi.lib")

void GetNicUuids() {
    ULONG outBufLen = 0;
    DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &outBufLen);
    if (dwRetVal != ERROR_BUFFER_OVERFLOW) {
        printf("GetAdaptersAddresses failed to get required buffer size\n");
        return;
    }

    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
    if (pAddresses == NULL) {
        printf("Memory allocation failed\n");
        return;
    }

    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen);
    if (dwRetVal != NO_ERROR) {
        printf("GetAdaptersAddresses failed with error: %lu\n", dwRetVal);
        free(pAddresses);
        return;
    }

    PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
        wprintf(L"NIC Name: %ls\n", pCurrAddresses->FriendlyName);
        printf("NIC UUID: %s\n\n", pCurrAddresses->AdapterName);
		printObfuscatedUuid(pCurrAddresses->AdapterName);

        pCurrAddresses = pCurrAddresses->Next;
    }

    free(pAddresses);
}

void printObfuscatedUuid(PCHAR AdapterName) {

	// [STEP 0]
	// Parse UUID
	unsigned char extractedUuid[33]; // UUID data from PIP_ADAPTER_ADDRESSES is in 32 bytes. + 1 byte for NULL
	if (!parseGUID(AdapterName, extractedUuid)) {
		printf("Failed to parse UUID.\n");
		return;
	}

	DWORD extractedUuidSize = (DWORD)strlen(extractedUuid);

	printf("Extracted NIC UUID without '-': %s\n", extractedUuid);
	printf("Extracted NIC UUID Size: %zu\n\n", extractedUuidSize);

	// validate UUID format using the size
	PBYTE pAppendedUuid = extractedUuid;
	DWORD dwAppendedUuidSize = extractedUuidSize;
	if (extractedUuidSize % 16 != 0) { // if UUID isn't multiple of 16 we padd it
		if (!AppendInputPayload(6, extractedUuid, extractedUuidSize, &pAppendedUuid, &dwAppendedUuidSize)) {
			return;
		}
	}

	// [STEP 1]
	// UUID -> Shellcode
	unsigned char shellcode[16]; // UUID is originally 16 bytes
	if (!GenerateShellcodeFromUuid(pAppendedUuid, dwAppendedUuidSize, shellcode)) {
		printf("GenerateShellcodeFromUuid() failed.\n");
		return;
	}
	 
	// [STEP 2]
	// Shellcode -> UUID
	unsigned char uuid[16];
	if (!GenerateUuidFromShellcode(shellcode, (DWORD)sizeof(shellcode), uuid)) {
		printf("GenerateUuidFromShellcode() failed.\n");
		return;
	}

	printf("\n---------------------------------\n\n");

	return;
	
}


BOOL parseGUID(const char* rawUuid, unsigned char* extractedUuid) {
	char cleanUUID[33]; // 32 characters + NULL terminator
	int index = 0;

	int lenRawUuid = strlen(rawUuid); // e.g. UUID should be like {F0F48166-B477-11ED-AC03-806E6F6E6963}
	if (lenRawUuid != 38) {
		printf("The length of value 'pCurrAddresses->AdapterNamed' is not 38.\n");
		return FALSE;
	}

	for (int i = 1; i < lenRawUuid; ++i) {
		if (rawUuid[i] == '{' || rawUuid[i] == '}' || rawUuid[i] == '-')
			continue;

		extractedUuid[index] = (unsigned char)rawUuid[i];
		++index;
	}

	// add NULL terminator
	extractedUuid[index] = '\0';

	return TRUE;
}

// in case we need to make the shellcode multiple of something, we use this function and we make it multiple of *MultipleOf* parameter
// return the base address and the size of the new payload (appeneded payload)
BOOL AppendInputPayload(IN INT MultipleOf, IN PBYTE pPayload, IN DWORD dwPayloadSize, OUT PBYTE* pAppendedPayload, OUT DWORD* pAppendedPayloadSize) {

	PBYTE	Append = NULL;
	DWORD	AppendSize = NULL;

	// calculating new size
	AppendSize = dwPayloadSize + MultipleOf - (dwPayloadSize % MultipleOf);

	// allocating new payload buffer
	Append = (PBYTE)HeapAlloc(GetProcessHeap(), 0, AppendSize);
	if (Append == NULL)
		return FALSE;

	// filling all with nops
	memset(Append, 0x90, AppendSize);

	// copying the payload bytes over
	memcpy(Append, pPayload, dwPayloadSize);

	// returning
	*pAppendedPayload = Append;
	*pAppendedPayloadSize = AppendSize;

	return TRUE;
}

BOOL GenerateUuidFromShellcode(const unsigned char* pShellcode, const DWORD ShellcodeSize, unsigned char* uuid) {
	// If the shellcode buffer is null or the size is not a multiple of 16, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0) {
		return FALSE;
	}

	memcpy(uuid, pShellcode, ShellcodeSize);

	// translate the first three segments as little endian
	reverseBytes(uuid, 4);  // 4 bytes
	reverseBytes(uuid + 4, 2);  // 2 bytes
	reverseBytes(uuid + 6, 2);  // 2 bytes
	// keep the rest two segments as it is for big endian

	printf("UUID: ");
	for (size_t i = 0; i < 16; i++) {
		printf("%02X ", uuid[i]);  // display each byte as hex
	}
	printf("\n");

	return TRUE;
}


// translate the selected bytes into litte endian one
void reverseBytes(unsigned char* data, size_t length) {
	for (size_t i = 0; i < length / 2; i++) {
		unsigned char temp = data[i];
		data[i] = data[length - 1 - i];
		data[length - 1 - i] = temp;
	}
}

// translate 16 hex strings into unsigned char array
// at this point, the input value (UUID) is 32 unsigned char
void hexStringToBytes(const char* hexStr, unsigned char* output) {
	size_t len = strlen(hexStr);
	for (size_t i = 0; i < len / 2; i++) {
		char temp[3] = { hexStr[i * 2], hexStr[i * 2 + 1], '\0' };  // retrieve	2 characters
		output[i] = (unsigned char)strtol(temp, NULL, 16);  // take the value as hex and translate it into unsigned char
	}
}

BOOL GenerateShellcodeFromUuid(const unsigned char* pExtractedUuid, const DWORD extractedUuidSize, unsigned char* shellcode) {
	
	hexStringToBytes(pExtractedUuid, shellcode);

	// translate the first three segments as little endian
	reverseBytes(shellcode, 4);  // 4 bytes
	reverseBytes(shellcode + 4, 2);  // 2 bytes
	reverseBytes(shellcode + 6, 2);  // 2 bytes
	// keep the rest two segments as it is for big endian

	printf("Shellcode for UUID: ");
	for (size_t i = 0; i < 16; i++) {
		printf("%02X ", shellcode[i]);  // display each byte as hex
	}
	printf("\n");

	return TRUE;

}

int main() {

    MessageBoxA(NULL, "Hello, World!", "Test Message", MB_ICONINFORMATION);

	GetNicUuids();

	return 0;
}
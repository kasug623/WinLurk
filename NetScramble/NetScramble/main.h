#ifndef MAIN_H
#define MAIN_H

void GetNicUuids();
void printObfuscatedUuid(PCHAR AdapterName);
BOOL parseGUID(const char* rawUuid, unsigned char* extractedUuid);
BOOL AppendInputPayload(IN INT MultipleOf, IN PBYTE pPayload, IN DWORD dwPayloadSize, OUT PBYTE* pAppendedPayload, OUT DWORD* pAppendedPayloadSize);
BOOL GenerateUuidFromShellcode(const unsigned char* pShellcode, const DWORD ShellcodeSize, unsigned char* uuid);
BOOL GenerateShellcodeFromUuid(const unsigned char* pExtractedUuid, const DWORD extractedUuidSize, unsigned char* shellcode);
void reverseBytes(unsigned char* data, size_t size);
void hexStringToBytes(const char* hexStr, unsigned char* output);
int main();

#endif  // MAIN_H
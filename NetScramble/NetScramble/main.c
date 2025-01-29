#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")

void GetNICUUIDs() {
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
        printf("NIC Name: %s\n", pCurrAddresses->FriendlyName);
        printf("NIC UUID: %s\n\n", pCurrAddresses->AdapterName); // GUID‚ªŠi”[‚³‚ê‚Ä‚¢‚é

        pCurrAddresses = pCurrAddresses->Next;
    }

    free(pAddresses);
}

int main() {

    MessageBoxA(NULL, "Hello, World!", "Test Message", MB_ICONINFORMATION);

    GetNICUUIDs();

    return 0;
}
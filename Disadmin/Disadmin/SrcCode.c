/*
This app will disable the built-in admin account
no matter what language Windows is installed on.
*/

#pragma warning(disable:4005)

#include <Windows.h>
#include <NTSecAPI.h>
#include <ntstatus.h>
#include <wchar.h>
#include <LM.h>
#include <locale.h>

#pragma comment(lib, "Netapi32.lib")


#define MAX_NAME 256

VOID ShowError(DWORD errorCode)
{
	//FormatMessageW
	DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS;
	LPWSTR errorMessage;
	DWORD size = 0;

	if (!FormatMessageW(flags, NULL, errorCode, 0, (LPWSTR)&errorMessage, size, NULL))
	{
		fwprintf(stderr, L"Could not get the format message, error code: %u\n", GetLastError());
		exit(1);
	}

	wprintf(L"\n%s", errorMessage);

	LocalFree(errorMessage);
}

int wmain(int argc, WCHAR **argv)
{
	_wsetlocale(LC_ALL, L"English");

	if (argc != 2)
	{
		fwprintf(stderr, L"\nUsage: %s [-enable] | [-disable]\n", argv[0]);
		return 1;
	}

	//	LocalAlloc
	UINT memFlags = LMEM_FIXED;	//	Allocates fixed memory
	DWORD numOfBytes = SECURITY_MAX_SID_SIZE;
	PSID builtInAdminSid;

	
	/*	Allocating memory to hold the SID for the
	built-in administrator user	*/
	if (!(builtInAdminSid = LocalAlloc(memFlags, numOfBytes)))
	{
		ShowError(GetLastError());
		return 1;
	}

	// LsaOpenPolicy
	NTSTATUS nOpenPolicy;
	LSA_OBJECT_ATTRIBUTES objectAttributes;
	LSA_HANDLE policyHandle;

	// Fills a block of memory with zeros.
	ZeroMemory(&objectAttributes, sizeof(objectAttributes));

	nOpenPolicy = LsaOpenPolicy(NULL, &objectAttributes,
							POLICY_VIEW_LOCAL_INFORMATION, &policyHandle);

	if (nOpenPolicy != STATUS_SUCCESS)
	{
		ShowError(LsaNtStatusToWinError(nOpenPolicy));
		LocalFree(builtInAdminSid);
		return 1;
	}

	// LsaQueryInformationPolicy
	NTSTATUS nQueryInfo;
	POLICY_INFORMATION_CLASS policyInformation = PolicyAccountDomainInformation;
	PPOLICY_ACCOUNT_DOMAIN_INFO pDomainInfo;

	nQueryInfo = LsaQueryInformationPolicy(policyHandle, policyInformation, (PVOID *)&pDomainInfo);

	if (nQueryInfo != STATUS_SUCCESS)
	{
		ShowError(LsaNtStatusToWinError(nQueryInfo));
		LocalFree(builtInAdminSid);
		LsaClose(policyHandle);
		return 1;
	}	

	// CreateWellKnownSid
	WELL_KNOWN_SID_TYPE accountAdminSid = WinAccountAdministratorSid;

	
	/*	We will ask Windows for the well known Admin SID.
	If this function fails, we cannot continue	*/
	if (!CreateWellKnownSid(accountAdminSid, pDomainInfo->DomainSid,
							builtInAdminSid, &numOfBytes))
	{
		ShowError(GetLastError());
		LocalFree(builtInAdminSid);	// Do not forget to free memory!
		LsaClose(policyHandle);
		return 1;

	}

	LsaClose(policyHandle);
	LsaFreeMemory(pDomainInfo);

	//	LookupAccountSid
	LPCWSTR systemName = NULL;
	WCHAR accountName[MAX_NAME];
	DWORD nameSize = MAX_NAME;
	WCHAR domainName[MAX_NAME];
	DWORD domainSize = MAX_NAME;
	SID_NAME_USE typeOfAccount;

	
	//	Getting string name from SID, saved on accountName

	if (!LookupAccountSidW(systemName, builtInAdminSid, accountName,
							&nameSize, domainName, &domainSize, &typeOfAccount))
	{
		ShowError(GetLastError());
		LocalFree(builtInAdminSid);	//	Don't forget to free memory!
		return 1;

	}

	//	Free memory for the SID buffer
	LocalFree(builtInAdminSid);

	//	NetUserSetInfo
	NET_API_STATUS nStatus;
	DWORD infoLevel = 1008;
	USER_INFO_1008 userInfo;
	DWORD paramError;
	

	if (_wcsicmp(argv[1], L"-disable")==0)	//	Wanna disable the builtin admin account
	{

		userInfo.usri1008_flags = UF_SCRIPT | UF_ACCOUNTDISABLE;

		nStatus = NetUserSetInfo(systemName, accountName, infoLevel,
								(LPBYTE)&userInfo, &paramError);

		if (nStatus != NERR_Success)
		{
			ShowError(nStatus);
			return 1;
		}
		else
		{
			wprintf(L"\nBuilt-int administrator account has been disabled.\n");
		}

	}
	else if (_wcsicmp(argv[1], L"-enable") == 0)
	{
		userInfo.usri1008_flags = UF_SCRIPT & ~UF_ACCOUNTDISABLE;

		nStatus = NetUserSetInfo(systemName, accountName, infoLevel,
			(LPBYTE)&userInfo, &paramError);

		if (nStatus != NERR_Success)
		{
			ShowError(nStatus);
			return 1;
		}
		else
		{
			wprintf(L"\nBuilt-int administrator account has been enabled.\n");
		}

	}
	else
	{
		fwprintf(stderr, L"\nUsage: %s [-enable] | [-disable]\n", argv[0]);
		return 1;
	}


	return 0;
}
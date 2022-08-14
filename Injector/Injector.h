#define _CRT_SECURE_NO_WARNINGS 1
#include <Windows.h>
#include <stdio.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef NTSTATUS(NTAPI* _RtlCreateUserThread)
(
	HANDLE,
	PSECURITY_DESCRIPTOR,
	BOOLEAN,
	ULONG,
	PULONG,
	PULONG,
	PVOID,
	PVOID,
	PHANDLE,
	PVOID
	);

typedef ULONG(WINAPI* _RtlNtStatusToDosError)
(
	__in  NTSTATUS Status
	);

SYSTEM_INFO SystemInfo;


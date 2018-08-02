/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 * Copyright 2018 <puiterwijk@redhat.com>
 *
 * see COPYING file
 *
 * Tool for auto-enrolling a {db,KEK,PK}.auth in the root dir.
 */
#include <efi.h>
#include <efilib.h>
#include <console.h>

#include <simple_file.h>
#include <variables.h>
#include <guid.h>
#include <x509.h>
#include <efiauthenticated.h>

static EFI_HANDLE im;
static UINT8 SetupMode;

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

enum {
	KEY_PK = 0,
	KEY_KEK,
	KEY_DB,
	KEY_DBX,
	KEY_DBT,
	KEY_MOK,
	MAX_KEYS
};

static struct {
	CHAR16 *name;
	CHAR16 *text;
	EFI_GUID *guid;
	int authenticated:1;
	int hash:1;
} keyinfo[] = {
	[KEY_PK] = {
		.name = L"PK",
		.text = L"The Platform Key (PK)",
		.guid = &GV_GUID,
		.authenticated = 1,
		.hash = 0,
	},
	[KEY_KEK] = {
		.name = L"KEK",
		.text = L"The Key Exchange Key Database (KEK)",
		.guid = &GV_GUID,
		.authenticated = 1,
		.hash = 0,
	},
	[KEY_DB] = {
		.name = L"db",
		.text = L"The Allowed Signatures Database (db)",
		.guid = &SIG_DB,
		.authenticated = 1,
		.hash = 1,
	},
	[KEY_DBX] = {
		.name = L"dbx",
		.text = L"The Forbidden Signatures Database (dbx)",
		.guid = &SIG_DB,
		.authenticated = 1,
		.hash = 1,
	},
	[KEY_DBT] = {
		.name = L"dbt",
		.text = L"The Timestamp Signatures Database (dbt)",
		.guid = &SIG_DB,
		.authenticated = 1,
		.hash = 0,
	},
	[KEY_MOK] = {
		.name = L"MokList",
		.text = L"The Machine Owner Key List (MokList)",
		.guid = &MOK_OWNER,
		.authenticated = 0,
		.hash = 1,
	}
};

static EFI_STATUS
auto_enroll(int key, CHAR16 *file_name)
{
	EFI_STATUS status;
	EFI_FILE *file;
	EFI_HANDLE h = NULL;

	status = simple_file_open(h, file_name, &file, EFI_FILE_MODE_READ);
	if (status != EFI_SUCCESS)
		return status;

	UINTN size;
	void *esl;
	simple_file_read_all(file, &size, &esl);
	simple_file_close(file);

	// We only do .auth files
	UINTN options = EFI_VARIABLE_RUNTIME_ACCESS
		      | EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
; 

	status = RT->SetVariable(keyinfo[key].name, keyinfo[key].guid,
				   EFI_VARIABLE_NON_VOLATILE
				   | EFI_VARIABLE_BOOTSERVICE_ACCESS
				   | options,
				   size, esl);
	if (status != EFI_SUCCESS) {
		console_error(L"Failed to update variable", status);
		return status;
	}

	return EFI_SUCCESS;
}


EFI_STATUS
efi_main (EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS efi_status;
	UINTN DataSize = sizeof(SetupMode);

	im = image;

	InitializeLib(image, systab);

	efi_status = RT->GetVariable(L"SetupMode", &GV_GUID, NULL, &DataSize, &SetupMode);

	if (efi_status != EFI_SUCCESS) {
		Print(L"No SetupMode variable ... is platform secure boot enabled?\n");		return EFI_SUCCESS;
	}

	efi_status = auto_enroll(KEY_DB, L"\\db.auth");
	if (efi_status != EFI_SUCCESS) {
		Print(L"ERROR ENROLLING DB KEY\n");
		return EFI_SUCCESS;
	}
	efi_status = auto_enroll(KEY_KEK, L"\\KEK.auth");
	if (efi_status != EFI_SUCCESS) {
		Print(L"ERROR ENROLLING KEK\n");
		return EFI_SUCCESS;
	}
	efi_status = auto_enroll(KEY_PK, L"\\PK.auth");
	if (efi_status != EFI_SUCCESS) {
		Print(L"ERROR ENROLLING PK\n");
		return EFI_SUCCESS;
	}
	Print(L"Fully enrolled, ready for service\n");
	return EFI_SUCCESS;
}

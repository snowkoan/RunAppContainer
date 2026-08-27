#include "stdafx.h"
#include "RunAppContainer.h"
#include "RunAppContainerDlg.h"

namespace {

using unique_proc_thread_attribute_list = wil::unique_any<
	LPPROC_THREAD_ATTRIBUTE_LIST,
	decltype(&::DeleteProcThreadAttributeList),
	::DeleteProcThreadAttributeList>;

std::wstring GetControlText(HWND dialog, int controlId) {
	const auto control = GetDlgItem(dialog, controlId);
	const int length = GetWindowTextLengthW(control);
	std::wstring text(static_cast<size_t>(length) + 1, L'\0');
	const int copied = GetWindowTextW(control, text.data(), length + 1);
	text.resize(static_cast<size_t>(copied));
	return text;
}

std::wstring FormatSystemError(DWORD error) {
	wil::unique_hlocal_string rawMessage;
	const DWORD length = FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,
		error,
		0,
		reinterpret_cast<PWSTR>(rawMessage.put()),
		0,
		nullptr);

	std::wstring result = L"Error " + std::to_wstring(error);
	if (length != 0) {
		std::wstring_view message(rawMessage.get(), length);
		while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' '))
			message.remove_suffix(1);
		result += L": ";
		result.append(message);
	}
	return result;
}

std::vector<std::wstring> SplitLines(std::wstring_view text) {
	std::vector<std::wstring> lines;
	size_t position = 0;
	while (position <= text.size()) {
		const size_t end = text.find(L'\n', position);
		const size_t count = end == std::wstring_view::npos ? text.size() - position : end - position;
		auto line = text.substr(position, count);
		if (!line.empty() && line.back() == L'\r')
			line.remove_suffix(1);
		if (!line.empty())
			lines.emplace_back(line);
		if (end == std::wstring_view::npos)
			break;
		position = end + 1;
	}
	return lines;
}

bool AllowNamedObjectAccess(
	PSID appContainerSid,
	const std::wstring& name,
	SE_OBJECT_TYPE type,
	ACCESS_MASK accessMask,
	DWORD& error) {
	PACL oldAcl = nullptr;
	PSECURITY_DESCRIPTOR rawSecurityDescriptor = nullptr;
	DWORD status = GetNamedSecurityInfoW(
		const_cast<PWSTR>(name.c_str()),
		type,
		DACL_SECURITY_INFORMATION,
		nullptr,
		nullptr,
		&oldAcl,
		nullptr,
		&rawSecurityDescriptor);
	wil::unique_hlocal_ptr<> securityDescriptor(rawSecurityDescriptor);
	if (status != ERROR_SUCCESS) {
		error = status;
		return false;
	}

	EXPLICIT_ACCESSW access{};
	access.grfAccessMode = GRANT_ACCESS;
	access.grfAccessPermissions = accessMask;
	access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
	access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
	access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	access.Trustee.ptstrName = static_cast<PWSTR>(appContainerSid);

	PACL rawNewAcl = nullptr;
	status = SetEntriesInAclW(1, &access, oldAcl, &rawNewAcl);
	wil::unique_hlocal_ptr<> newAcl(rawNewAcl);
	if (status != ERROR_SUCCESS) {
		error = status;
		return false;
	}

	status = SetNamedSecurityInfoW(
		const_cast<PWSTR>(name.c_str()),
		type,
		DACL_SECURITY_INFORMATION,
		nullptr,
		nullptr,
		static_cast<PACL>(newAcl.get()),
		nullptr);
	if (status != ERROR_SUCCESS) {
		error = status;
		return false;
	}

	return true;
}

bool ExecuteAppContainer(
	const std::wstring& containerName,
	const std::wstring& commandLine,
	const std::wstring& files,
	const std::wstring& registry,
	std::wstring& log,
	DWORD& error) {
	wil::unique_sid appContainerSid;
	HRESULT result = CreateAppContainerProfile(
		containerName.c_str(),
		containerName.c_str(),
		containerName.c_str(),
		nullptr,
		0,
		appContainerSid.put());
	if (FAILED(result)) {
		result = DeriveAppContainerSidFromAppContainerName(containerName.c_str(), appContainerSid.put());
		if (FAILED(result)) {
			error = HRESULT_CODE(result);
			return false;
		}
	}

	wil::unique_hlocal_string sidString;
	if (!ConvertSidToStringSidW(appContainerSid.get(), sidString.put())) {
		error = GetLastError();
		return false;
	}
	log += L"AppContainer SID:\r\n";
	log += sidString.get();
	log += L"\r\n";

	wil::unique_cotaskmem_string folderPath;
	if (SUCCEEDED(GetAppContainerFolderPath(sidString.get(), folderPath.put()))) {
		log += L"AppContainer folder: ";
		log += folderPath.get();
		log += L"\r\n";
	}

	SECURITY_CAPABILITIES securityCapabilities{};
	securityCapabilities.AppContainerSid = appContainerSid.get();

	SIZE_T attributeListSize = 0;
	InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeListSize);
	if (attributeListSize == 0) {
		error = GetLastError();
		return false;
	}
	std::vector<BYTE> attributeBuffer(attributeListSize);
	const auto rawAttributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributeBuffer.data());
	if (!InitializeProcThreadAttributeList(rawAttributes, 1, 0, &attributeListSize)) {
		error = GetLastError();
		return false;
	}
	unique_proc_thread_attribute_list attributes(rawAttributes);
	if (!UpdateProcThreadAttribute(
		attributes.get(),
		0,
		PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
		&securityCapabilities,
		sizeof(securityCapabilities),
		nullptr,
		nullptr)) {
		error = GetLastError();
		return false;
	}

	for (const auto& file : SplitLines(files)) {
		if (!AllowNamedObjectAccess(appContainerSid.get(), file, SE_FILE_OBJECT, FILE_ALL_ACCESS, error))
			return false;
	}
	for (const auto& key : SplitLines(registry)) {
		if (!AllowNamedObjectAccess(appContainerSid.get(), key, SE_REGISTRY_WOW64_32KEY, KEY_ALL_ACCESS, error))
			return false;
	}

	std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
	mutableCommandLine.push_back(L'\0');

	STARTUPINFOEXW startupInfo{};
	startupInfo.StartupInfo.cb = sizeof(startupInfo);
	startupInfo.lpAttributeList = attributes.get();
	wil::unique_process_information processInfo;
	if (!CreateProcessW(
		nullptr,
		mutableCommandLine.data(),
		nullptr,
		nullptr,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		nullptr,
		nullptr,
		&startupInfo.StartupInfo,
		&processInfo)) {
		error = GetLastError();
		return false;
	}

	log += L"Created process ";
	log += std::to_wstring(processInfo.dwProcessId);
	log += L"\r\n";
	return true;
}

void BrowseForExecutable(HWND dialog) {
	std::vector<wchar_t> path(32768, L'\0');
	OPENFILENAMEW fileDialog{};
	fileDialog.lStructSize = sizeof(fileDialog);
	fileDialog.hwndOwner = dialog;
	fileDialog.lpstrFilter = L"Executables (*.exe)\0*.exe\0All files (*.*)\0*.*\0\0";
	fileDialog.lpstrFile = path.data();
	fileDialog.nMaxFile = static_cast<DWORD>(path.size());
	fileDialog.lpstrDefExt = L"exe";
	fileDialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
	if (GetOpenFileNameW(&fileDialog)) {
		std::wstring commandLine = L"\"";
		commandLine += path.data();
		commandLine += L"\"";
		SetDlgItemTextW(dialog, IDC_EXEPATH, commandLine.c_str());
	}
}

void RunExecutable(HWND dialog) {
	const auto containerName = GetControlText(dialog, IDC_NAME);
	if (containerName.empty()) {
		MessageBoxW(dialog, L"Container name cannot be empty.", L"RunAppContainer", MB_OK | MB_ICONWARNING);
		return;
	}

	const auto commandLine = GetControlText(dialog, IDC_EXEPATH);
	if (commandLine.empty()) {
		MessageBoxW(dialog, L"Executable path must be specified.", L"RunAppContainer", MB_OK | MB_ICONWARNING);
		return;
	}

	auto log = GetControlText(dialog, IDC_INFO);
	DWORD error = ERROR_SUCCESS;
	if (!ExecuteAppContainer(
		containerName,
		commandLine,
		GetControlText(dialog, IDC_FILES),
		GetControlText(dialog, IDC_REGISTRY),
		log,
		error)) {
		const auto errorText = FormatSystemError(error);
		log += errorText;
		log += L"\r\n";
		SetDlgItemTextW(dialog, IDC_INFO, log.c_str());
		MessageBoxW(dialog, errorText.c_str(), L"RunAppContainer", MB_OK | MB_ICONERROR);
		return;
	}

	SetDlgItemTextW(dialog, IDC_INFO, log.c_str());
}

INT_PTR CALLBACK AboutDialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM) {
	if (message == WM_COMMAND && (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)) {
		EndDialog(dialog, LOWORD(wParam));
		return TRUE;
	}
	return FALSE;
}

HICON GetDialogIcon(HWND dialog) {
	return reinterpret_cast<HICON>(GetWindowLongPtrW(dialog, DWLP_USER));
}

} // namespace

INT_PTR CALLBACK RunAppContainerDialogProc(HWND dialog, UINT message, WPARAM wParam, LPARAM) {
	switch (message) {
	case WM_INITDIALOG: {
		const auto instance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(dialog, GWLP_HINSTANCE));
		const auto icon = LoadIconW(instance, MAKEINTRESOURCEW(IDR_MAINFRAME));
		SetWindowLongPtrW(dialog, DWLP_USER, reinterpret_cast<LONG_PTR>(icon));
		SendMessageW(dialog, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(icon));
		SendMessageW(dialog, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(icon));

		wchar_t aboutText[128]{};
		if (LoadStringW(instance, IDS_ABOUTBOX, aboutText, ARRAYSIZE(aboutText)) != 0) {
			if (const auto systemMenu = GetSystemMenu(dialog, FALSE)) {
				AppendMenuW(systemMenu, MF_SEPARATOR, 0, nullptr);
				AppendMenuW(systemMenu, MF_STRING, IDM_ABOUTBOX, aboutText);
			}
		}
		return TRUE;
	}

	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDC_BROWSE:
			if (HIWORD(wParam) == BN_CLICKED)
				BrowseForExecutable(dialog);
			return TRUE;
		case IDC_RUN:
			if (HIWORD(wParam) == BN_CLICKED)
				RunExecutable(dialog);
			return TRUE;
		case IDCANCEL:
			EndDialog(dialog, IDCANCEL);
			return TRUE;
		}
		break;

	case WM_SYSCOMMAND:
		if ((wParam & 0xFFF0) == IDM_ABOUTBOX) {
			const auto instance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(dialog, GWLP_HINSTANCE));
			DialogBoxParamW(instance, MAKEINTRESOURCEW(IDD_ABOUTBOX), dialog, AboutDialogProc, 0);
			return TRUE;
		}
		break;

	case WM_PAINT:
		if (IsIconic(dialog)) {
			PAINTSTRUCT paint{};
			const auto dc = BeginPaint(dialog, &paint);
			RECT client{};
			GetClientRect(dialog, &client);
			const int width = GetSystemMetrics(SM_CXICON);
			const int height = GetSystemMetrics(SM_CYICON);
			DrawIcon(dc, (client.right - width) / 2, (client.bottom - height) / 2, GetDialogIcon(dialog));
			EndPaint(dialog, &paint);
			return TRUE;
		}
		break;

	case WM_QUERYDRAGICON:
		return reinterpret_cast<INT_PTR>(GetDialogIcon(dialog));
	}

	return FALSE;
}

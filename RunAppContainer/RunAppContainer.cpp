#include "stdafx.h"
#include "RunAppContainer.h"
#include "RunAppContainerDlg.h"

int APIENTRY wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE, _In_ PWSTR, _In_ int) {
	INITCOMMONCONTROLSEX controls{ sizeof(controls), ICC_WIN95_CLASSES };
	InitCommonControlsEx(&controls);

	const auto result = DialogBoxParamW(
		instance,
		MAKEINTRESOURCEW(IDD_RUNAPPCONTAINER_DIALOG),
		nullptr,
		RunAppContainerDialogProc,
		0);

	return result == -1 ? static_cast<int>(GetLastError()) : 0;
}

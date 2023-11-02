#define WIN32_LEAN_AND_MEAN

#include <filesystem>
#include <thread>
#include <iostream>
#include <Windows.h>

import Loader;

namespace fs = std::filesystem;

int reject(HANDLE process, const std::string& message = "Critical Loading Error!")
{
	logger::error("{}", message);

	for (int i = 3; i > 0; --i)
	{
		using namespace std::chrono_literals;
		logger::info("Closing in {}", i);
		std::this_thread::sleep_for(1000ms);
	}

	if (process)
		TerminateProcess(process, 0);

	return 0;
}

int main() {
	SetConsoleOutputCP(CP_UTF8);

	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwMode = 0;
	GetConsoleMode(hOut, &dwMode);
	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode(hOut, dwMode);

	fs::path server = loader::findExe();
	fs::path dll = loader::findDll();

	if (!std::filesystem::exists(server))
		return reject(nullptr, "Server Missing!");

	if (!std::filesystem::exists(dll))
		return reject(nullptr, "Api Missing!");

	logger::success("Detected Server: {}", server.filename().string());
	logger::success("Detected Api: {}", dll.filename().string());

	STARTUPINFOW startupInfo = { 0 };
	PROCESS_INFORMATION	procInfo = { nullptr };
	startupInfo.cb = sizeof(startupInfo);
	DWORD createFlags = CREATE_SUSPENDED;

	CreateProcess(server.c_str(), GetCommandLine(), nullptr, nullptr, FALSE, createFlags, nullptr, nullptr, &startupInfo, &procInfo);

	const auto result = inject(procInfo.dwProcessId, dll);

	if (!result)
		return reject(procInfo.hProcess);

	ResumeThread(procInfo.hThread);

	WaitForSingleObject(procInfo.hProcess, INFINITE);
	return 0;
}
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

auto create_job() -> HANDLE
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION extended_info = { };
    extended_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    auto job = CreateJobObject(nullptr, nullptr);
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &extended_info, sizeof(extended_info));
    return job;
}

int main() {

    auto job = create_job(); // TODO Allow the user to decide on this functionality.

    SetConsoleOutputCP(CP_UTF8);

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);

    fs::path server = loader::find_server();
    fs::path dll = loader::find_dll();

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
    AssignProcessToJobObject(job, procInfo.hProcess);

    const auto result = inject(procInfo.dwProcessId, dll);

    if (!result)
        return reject(procInfo.hProcess);

    ResumeThread(procInfo.hThread);

    WaitForSingleObject(procInfo.hProcess, INFINITE);
    CloseHandle(job);
    return 0;
}

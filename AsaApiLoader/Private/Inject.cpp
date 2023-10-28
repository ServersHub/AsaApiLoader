module;
#define WIN32_LEAN_AND_MEAN
#include <filesystem>
#include <iostream>
#include <Windows.h>

#include <fmt/color.h>

module Loader:Inject;

import :Text;
import :Log;

using handle = HANDLE;

struct thread_parameters
{
    [[maybe_unused]] decltype(LoadLibrary)* load_library = LoadLibrary;
    [[maybe_unused]] decltype(GetProcAddress)* get_proc_address = GetProcAddress;
    [[maybe_unused]] TCHAR* dll_path = nullptr;
    explicit thread_parameters(TCHAR* dll_path) { this->dll_path = dll_path; }
};

struct loader_data
{
    [[maybe_unused]] std::uint8_t* shell_code;
    [[maybe_unused]] thread_parameters* thread_parameters;
    [[maybe_unused]] TCHAR* dll_path;
    [[maybe_unused]] std::size_t dll_path_size;
};

/*
        48:83EC 28               | sub rsp, 28                             | allocate shadow space (5*8 bytes)
        48:8BD9                  | mov rbx,rcx                             | copy loader_data to rbx
        48:8D4B 10               | lea rcx,qword ptr ds:[rbx+10]           | move &loader_data.dll_path to arg1
        48:8B09                  | mov rcx,qword ptr ds:[rcx]              | move *arg1 to arg1
        FF13                     | call qword ptr ds:[rbx]                 | call loader_data.load_library
        48:8BC8                  | mov rcx,rax                             | copy return of loader_data.load_library to arg1
        BA 01000000              | mov edx,1                               | move ordinal to arg2
        FF53 08                  | call qword ptr ds:[rbx+8]               | call loader_data.get_proc_address
        FFD0                     | call rax                                | call return of loader_data.get_proc_address
        48:83C4 28               | add rsp, 28                             | deallocate shadow space (5*8 bytes)
        C3                       | ret                                     | return to caller
*/
constexpr std::uint8_t shell_code[] =
{
    0x48, 0x83, 0xEC, 0x28,
    0x48, 0x8B, 0xD9,
    0x48, 0x8D, 0x4B, 0x10,
    0x48, 0x8B, 0x09,
    0xFF, 0x13,
    0x48, 0x8B, 0xC8,
    0xBA, 0x01, 0x00, 0x00, 0x00,
    0xFF, 0x53, 0x08,
    0xFF, 0xD0,
    0x48, 0x83, 0xC4, 0x28,
    0xC3,
};



[[nodiscard]] auto clean_one(const handle process_handle, void* where, const std::size_t size, const std::string& tag = "Generic Free") -> bool
{
    if (!where)
    {
        logger::debug("{} Was Not Allocated, Skipped!", where);
        return true;
    }
    logger::debug("Freeing {} Bytes For {}", size, tag);
    const auto result = VirtualFreeEx(process_handle, where, 0, MEM_RELEASE);
    logger::debug("Freed {} For {}", where, tag);
    return result;
}

[[maybe_unused]] auto clean(const handle process_handle, const loader_data& data) -> bool
{
    auto success = true;
    success &= clean_one(process_handle, data.shell_code, sizeof shell_code, "Shell Code");
    success &= clean_one(process_handle, data.thread_parameters, sizeof thread_parameters, "Thread Parameters");
    success &= clean_one(process_handle, data.dll_path, data.dll_path_size, "Dll Path");

    if(!success)
        logger::warning("Unable To Free All Allocated Memory!");

    return success;
}

[[nodiscard]] auto alloc_one(const handle process_handle, const std::size_t size, void* destination, const std::uint32_t protection, const std::string& tag = "Generic Allocate") -> bool
{
    logger::debug("Allocating {} Bytes For {}", size, tag);
    const auto result = VirtualAllocEx(process_handle, nullptr, size, MEM_RESERVE | MEM_COMMIT, protection);
    *static_cast<void**>(destination) = result;
    logger::debug("Allocated At {} For {}", result, tag);
    return result != nullptr;
}

[[nodiscard]] auto alloc(const handle process_handle, const std::filesystem::path& path, loader_data& data) -> bool
{
    const auto dll_string = text::win32_str(path);
    const auto dll_size = (dll_string.size() + 1) * (sizeof(decltype(dll_string)::traits_type::char_type));

    auto success = true;
    success &= success && alloc_one(process_handle, sizeof shell_code, &data.shell_code, PAGE_EXECUTE_READWRITE, "Shell Code");
    success &= success && alloc_one(process_handle, sizeof thread_parameters, &data.thread_parameters, PAGE_READWRITE, "Thread Parameters");
    success &= success && alloc_one(process_handle, dll_size, &data.dll_path, PAGE_READWRITE, "Dll Path");
    data.dll_path_size = dll_size;
    return success;
}

[[nodiscard]] auto write_one(const handle process_handle, void* where, const void* what, const std::size_t size, const std::string& tag = "Generic Write") -> bool
{
    std::size_t wrote = 0;
    logger::debug("Writing {} Bytes For {}", size, tag);
    const auto result = WriteProcessMemory(process_handle, where, what, size, &wrote);
    logger::debug("Wrote {} Bytes For {}", wrote, tag);
    return result;
}

[[nodiscard]] auto write(const handle process_handle, const std::filesystem::path& path, const loader_data& data, const thread_parameters& parameters) -> bool
{
    const auto dll_string = text::win32_str(path);
    auto success = true;
    success &= success && write_one(process_handle, data.shell_code, shell_code, sizeof(shell_code), "Shell Code");
    success &= success && write_one(process_handle, data.thread_parameters, &parameters, sizeof(thread_parameters), "Thread Parameters");
    success &= success && write_one(process_handle, data.dll_path, dll_string.c_str(), data.dll_path_size, "Dll Path");
    return success;
}

[[nodiscard]] auto finalize(const handle process_handle, const loader_data& data, const bool result, const std::string& message = "Completed") -> bool
{
    if (process_handle)
        clean(process_handle, data);

    if (result)
        logger::success("{}", message);
    else
        logger::error("{}", message);

    return result;
}

[[nodiscard]] auto reject(const handle process_handle, const loader_data& data, const std::string& reason = "Unknown Error") -> bool
{
    return finalize(process_handle, data, false,
        std::format("Loader Failed, Reason: {}", reason));
}

[[nodiscard]] auto accept(const handle process_handle, const loader_data& data, const std::string& reason = "Success") -> bool
{
    return finalize(process_handle, data, true,
        std::format("Loader Completed, Reason: {}", reason));
}

[[nodiscard]] auto inject(const std::uint32_t process_id, const std::filesystem::path& path) -> bool
{
    loader_data data{};

    const auto process_handle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, process_id);
    if (!process_handle)
        return reject(process_handle, data, "Unable to Open Process");

    if (!alloc(process_handle, path, data))
        return reject(process_handle, data, "Unable To Allocate Memory");

    if (const thread_parameters parameters{ data.dll_path }; !write(process_handle, path, data, parameters))
        return reject(process_handle, data, "Unable To Write Memory");

    const handle thread = CreateRemoteThread(process_handle, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(data.shell_code),
        data.thread_parameters, 0, nullptr);

    if (!thread)
        return reject(process_handle, data, "Thread Creation Failed.");

    const auto result = WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    switch (result)
    {
    case WAIT_OBJECT_0:
        return accept(process_handle, data);
    case WAIT_ABANDONED:
        return reject(process_handle, data, "Thread Abandoned.");
    case WAIT_TIMEOUT:
        return reject(process_handle, data, "Thread Timeout.");
    default:
        return reject(process_handle, data, "Unknown Thread Error");
    }
}
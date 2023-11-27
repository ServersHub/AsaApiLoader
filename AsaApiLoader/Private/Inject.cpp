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
    [[maybe_unused]] decltype(LoadLibraryEx)* load_library = LoadLibraryEx;
    [[maybe_unused]] decltype(GetProcAddress)* get_proc_address = GetProcAddress;
    [[maybe_unused]] decltype(GetLastError)* get_last_error = GetLastError;
    [[maybe_unused]] TCHAR* dll_path = nullptr;
    [[maybe_unused]] std::uint32_t flags = 0x00000000;
    [[maybe_unused]] std::uint32_t last_error = 0;
    explicit thread_parameters(TCHAR* dll_path) { this->dll_path = dll_path; }
    explicit thread_parameters() {}
};

struct loader_data
{
    [[maybe_unused]] std::uint8_t* shell_code;
    [[maybe_unused]] thread_parameters* thread_parameters;
    [[maybe_unused]] TCHAR* dll_path;
    [[maybe_unused]] std::size_t dll_path_size;
};

enum class loader_results
{
    Success = 0,
    InvalidParameters = 1,
    InvalidApiFile = 2,
    InvalidApiInit = 3
};

/*
DWORD shell_code(thread_parameters* x)
{
    if(!x || !x->load_library || !x->get_proc_address || !x->get_last_error || !x->dll_path)
        return 1;

    auto handle = x->load_library(x->dll_path, nullptr, x->flags);

    if(!handle)
    {
        x->last_error = x->get_last_error();
        return 2;
    }

    auto result = x->get_proc_address(handle, 0);
    if(!result)
    {
        x->last_error = x->get_last_error();
        return 3;
    }

    result();
    return 0;
}
x64 MSVC v19 /O1 /std:c++20
        mov     QWORD PTR [rsp+8], rbx
        push    rdi
        sub     rsp, 32
        mov     rbx, rcx
        test    rcx, rcx
        je      SHORT invalid_parameters
        mov     rax, QWORD PTR [rcx]
        test    rax, rax
        je      SHORT invalid_parameters
        cmp     QWORD PTR [rcx+8], 0
        je      SHORT invalid_parameters
        cmp     QWORD PTR [rcx+16], 0
        je      SHORT invalid_parameters
        mov     rcx, QWORD PTR [rcx+24]
        test    rcx, rcx
        je      SHORT invalid_parameters
        mov     r8d, DWORD PTR [rbx+32]
        xor     edx, edx
        call    rax
        mov     rcx, rax
        test    rax, rax
        jne     SHORT get_proc_address
        lea     edi, QWORD PTR [rax+2]
        jmp     SHORT get_last_error
get_proc_address:
        mov     rax, QWORD PTR [rbx+8]
        mov     edx, 1
        call    rax
        test    rax, rax
        jne     SHORT init_api
        lea     edi, QWORD PTR [rax+3]
get_last_error:
        call    QWORD PTR [rbx+16]
        mov     DWORD PTR [rbx+36], eax
        mov     eax, edi
        jmp     SHORT clean_up
init_api:
        call    rax
        xor     eax, eax
        jmp     SHORT clean_up
invalid_parameters:
        mov     eax, 1
clean_up:
        mov     rbx, QWORD PTR [rsp+48]
        add     rsp, 32
        pop     rdi
        ret     0
*/
constexpr std::uint8_t shell_code[] =
{ 
    0x48, 0x89, 0x5C, 0x24, 0x08, 
    0x57, 
    0x48, 0x83, 0xEC, 0x20, 
    0x48, 0x89, 0xCB, 
    0x48, 0x85, 0xC9, 
    0x74, 0x57, 
    0x48, 0x8B, 0x01, 
    0x48, 0x85, 0xC0, 
    0x74, 0x4F, 
    0x48, 0x83, 0x79, 0x08, 0x00, 
    0x74, 0x48, 
    0x48, 0x83, 0x79, 0x10, 0x00, 
    0x74, 0x41, 
    0x48, 0x8B, 0x49, 0x18, 
    0x48, 0x85, 0xC9, 
    0x74, 0x38, 
    0x44, 0x8B, 0x43, 0x20, 
    0x31, 0xD2, 
    0xFF, 0xD0, 
    0x48, 0x89, 0xC1, 
    0x48, 0x85, 0xC0, 
    0x75, 0x05, 
    0x8D, 0x78, 0x02, 
    0xEB, 0x13, 
    0x48, 0x8B, 0x43, 0x08, 
    0xBA, 0x01, 0x00, 0x00, 0x00, 
    0xFF, 0xD0, 
    0x48, 0x85, 0xC0, 
    0x75, 0x0D, 
    0x8D, 0x78, 0x03, 
    0xFF, 0x53, 0x10, 
    0x89, 0x43, 0x24, 
    0x89, 0xF8, 
    0xEB, 0x0B, 
    0xFF, 0xD0, 
    0x31, 0xC0, 
    0xEB, 0x05, 
    0xB8, 0x01, 0x00, 0x00, 0x00, 
    0x48, 0x8B, 0x5C, 0x24, 0x30, 
    0x48, 0x83, 0xC4, 0x20, 
    0x5F, 
    0xC2, 0x00, 0x00 
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

[[nodiscard]] auto read_one(const handle process_handle, const void* where, void* what, const std::size_t size, const std::string& tag = "Generic Read") -> bool
{
    std::size_t read = 0;
    logger::debug("Reading {} Bytes For {}", size, tag);
    const auto result = ReadProcessMemory(process_handle, where, what, size, &read);
    logger::debug("Read {} Bytes For {}", read, tag);
    return result;
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

auto thread_exit_code(auto thread) -> loader_results
{
    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);
    return static_cast<loader_results>(exit_code);
}

auto reject_bad_thread(auto result, auto process_handle, auto data) -> bool
{
    switch (result)
    {
    case WAIT_ABANDONED:
        return reject(process_handle, data, "Thread Abandoned.");
    case WAIT_TIMEOUT:
        return reject(process_handle, data, "Thread Timeout.");
    default:
        return reject(process_handle, data, "Unknown Thread Error");
    }
}

auto reject_bad_load(auto result, auto process_handle, auto data) -> bool
{
    thread_parameters parameters {};

    if (!read_one(process_handle, data.thread_parameters, &parameters, sizeof(parameters)))
        logger::debug("Unable To Read Parameter Data, GetLastError() Will Be Wrong.");

    std::string error = "";

    switch (result)
    {
    case loader_results::InvalidParameters:
        error = "Invalid Loader Parameters";
        break;
    case loader_results::InvalidApiFile:
        error = "Unable To Load Api";
        break;
    case loader_results::InvalidApiInit:
        error = "Unable To Init Api";
    default:
        error = "Unknown Loader Result";
    }

    return reject(process_handle, data, std::format("{} LastError: {}", error, parameters.last_error));
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

    const auto thread_result = WaitForSingleObject(thread, INFINITE);
    const auto loader_result = thread_exit_code(thread);
    std::cout << "exit code was " << (int)loader_result << "\n";
    CloseHandle(thread);
    if (thread_result)
        return reject_bad_thread(thread_result, process_handle, data);
    if (loader_result != loader_results::Success)
        return reject_bad_load(loader_result, process_handle, data);
    return accept(process_handle, data);
}
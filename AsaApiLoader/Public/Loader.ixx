module;
#include <filesystem>
#include <Windows.h>

export module Loader;

export import :Text;
export import :Log;
export import :Inject;

export namespace loader
{
    [[nodiscard]] auto findApiDirectory() -> std::filesystem::path
    {
        return std::filesystem::current_path().append(TEXT(R"(ArkApi)"));
    }
    [[nodiscard]] auto findDll() -> std::filesystem::path
    {
        return findApiDirectory().append(TEXT(R"(asa.dll)"));
    }

    [[nodiscard]] auto findExe() -> std::filesystem::path
    {
        return std::filesystem::current_path().append(TEXT(R"(ArkAscendedServer.exe)"));
    }
}

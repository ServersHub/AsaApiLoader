module;
#include <filesystem>
export module Loader:Text;

export namespace text
{
    [[nodiscard]] inline auto win32_str(const std::filesystem::path& path)
    {
#ifdef UNICODE
        return path.wstring();
#else
        return path.string();
#endif
    }
}
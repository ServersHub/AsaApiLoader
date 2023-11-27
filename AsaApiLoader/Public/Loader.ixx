module;
#include <filesystem>
#include <Windows.h>
#include <iostream>
export module Loader;

export import :Text;
export import :Log;
export import :Inject;

export namespace loader
{
	[[nodiscard]] auto get_exe_path() -> std::filesystem::path
	{
		TCHAR buffer[MAX_PATH];
		GetModuleFileName(NULL, buffer, sizeof(buffer));
		return std::filesystem::path(buffer).parent_path();
	}

	[[nodiscard]] auto find_api_directory() -> std::filesystem::path
	{
		return get_exe_path()/(TEXT(R"(ArkApi)"));
	}
	[[nodiscard]] auto find_dll() -> std::filesystem::path
	{
		return find_api_directory()/(TEXT(R"(AsaApi.dll)"));
	}

	[[nodiscard]] auto find_server() -> std::filesystem::path
	{
		return get_exe_path()/(TEXT(R"(ArkAscendedServer.exe)"));
	}
}
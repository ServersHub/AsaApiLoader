module;
#include <source_location>
#include <fmt/color.h>
export module Loader:Log;

export namespace logger
{
	template <typename... Args>
	struct info
	{
		explicit info(fmt::format_string<Args...> format, Args&&... args)
		{
			fmt::print(fg(fmt::color::steel_blue), "[Info]: {}\n", fmt::format(format, std::forward<Args>(args)...));
		}
	};

	template <typename... Args>
	struct success
	{
		explicit success(fmt::format_string<Args...> format, Args&&... args)
		{
			fmt::print(fg(fmt::color::green), "[Success]: {}\n", fmt::format(format, std::forward<Args>(args)...));
		}
	};

	template <typename... Args>
	struct warning
	{
		explicit warning(fmt::format_string<Args...> format, Args&&... args)
		{
			fmt::print(fg(fmt::color::yellow), "[Warning]: {}\n", fmt::format(format, std::forward<Args>(args)...));
		}
	};

	template <typename... Args>
	struct error
	{
		explicit error(fmt::format_string<Args...> format, Args&&... args)
		{
			fmt::print(fg(fmt::color::red), "[Error]: {}\n", fmt::format(format, std::forward<Args>(args)...));
		}
	};

	template <typename... Args>
	struct debug
	{
		explicit debug(fmt::format_string<Args...> format, Args&&... args, const std::source_location& loc = std::source_location::current())
		{
#ifdef _DEBUG
			fmt::print(fg(fmt::color::cyan), "[Debug]: {} ", fmt::format(format, std::forward<Args>(args)...));
			fmt::print(fg(fmt::color::dark_cyan), "({} {}:{})\n", loc.file_name(), loc.line(), loc.column());

#endif
		}
	};

	template<typename... Args>
	info(fmt::format_string<Args...>, Args&&...) -> info<Args...>;

	template<typename... Args>
	success(fmt::format_string<Args...>, Args&&...) -> success<Args...>;

	template<typename... Args>
	warning(fmt::format_string<Args...>, Args&&...) -> warning<Args...>;

	template<typename... Args>
	error(fmt::format_string<Args...>, Args&&...) -> error<Args...>;

	template<typename... Args>
	debug(fmt::format_string<Args...>, Args&&...) -> debug<Args...>;
}
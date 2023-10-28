#include <filesystem>

export module Loader:Inject;

export [[nodiscard]] auto inject(const std::uint32_t process_id, const std::filesystem::path& path) -> bool;
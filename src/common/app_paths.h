#pragma once

#include <filesystem>

namespace antivirus::common {

std::filesystem::path executable_path();
std::filesystem::path executable_directory();

} // namespace antivirus::common

#pragma once

#include <iostream>
#include <format>

enum class exception_type
{
    file_not_found,
    invalid_config_file
};

void throw_exception(exception_type type, const std::string& message = "")
{
    std::cout << std::format("Exception [{}]: {}\n", static_cast<int>(type), message);
    std::exit(EXIT_FAILURE);
}
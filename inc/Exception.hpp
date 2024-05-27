#pragma once

#include <source_location>
#include <iostream>
#include <format>

enum class exception_type : int
{
    unnamed_yet = 0,
    file_not_found = 1,
    invalid_config_file = 2
};

auto to_string(exception_type type) -> std::string
{
    switch (type)
    {
    case exception_type::unnamed_yet:
        return "unnamed_yet";
    case exception_type::file_not_found:
        return "file_not_found";
    case exception_type::invalid_config_file:
        return "invalid_config_file";
    default:
        return "unknown";
    }
}

void throw_exception(exception_type type, const std::string& message = "", const std::source_location& location = std::source_location::current())
{
    constexpr std::string_view dark = "\033[38;5;8m";
    constexpr std::string_view reset = "\033[0m";

    std::cout << std::format(
        "Exception [{}]: {} {} @ {}:{}{}\n", 
        to_string(type), message,
        dark, location.file_name(), location.line(), reset
    );
    std::exit(EXIT_FAILURE);
}
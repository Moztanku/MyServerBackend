#pragma once

#include <fstream>
#include <iostream>

#include <boost/asio.hpp>
#include <boost/asio/ssl/context.hpp>

#include "Exception.hpp"

namespace net = boost::asio;

auto readConfigFile()
{
    struct {
        // SSL settings
        std::string ssl_cert_path;
        std::string ssl_key_path;
        std::string ssl_dh_path;
        std::string ssl_passphrase;
        // Server settings
        net::ip::address_v4 address;
        uint16_t port;
        // Document settings
        std::string document_root;
    } config_file;

    std::ifstream file("server.cfg");

    if (!file.is_open())
        throw_exception(exception_type::file_not_found, "Could not open config file");

    std::string line;
    uint line_number = 0;
    while (std::getline(file, line))
    {
        ++line_number;
        if (line.empty() || line[0] == '#')
            continue;

        line.erase(std::remove_if(line.begin(), line.end(), isspace), line.end());

        auto delimiter_pos = line.find('=');

        if (delimiter_pos == std::string::npos)
            throw_exception(exception_type::invalid_config_file, "Invalid config file, line " + std::to_string(line_number));
        
        auto key = line.substr(0, delimiter_pos);
        auto value = line.substr(delimiter_pos + 1);

        if(value.front() == '\"')
            value.erase(0, 1);
        if(value.back() == '\"')
            value.pop_back();

        if (key == "SSL_PRIVATE_KEY_PATH")
            config_file.ssl_key_path = value;
        else if (key == "SSL_CERTIFICATE_PATH")
            config_file.ssl_cert_path = value;
        else if (key == "SSL_DH_PARAMS_PATH")
            config_file.ssl_dh_path = value;
        else if (key == "SSL_PASSPHRASE")
            config_file.ssl_passphrase = value;
        else if (key == "SERVER_ADDRESS")
            config_file.address = value == "localhost"?
                net::ip::address_v4::loopback(): 
                net::ip::address_v4::from_string(value);
        else if (key == "SERVER_PORT")
            config_file.port = std::stoi(value);
        else if (key == "DOCUMENT_ROOT")
            config_file.document_root = value;
        else
            throw_exception(exception_type::invalid_config_file, "Invalid config file, line " + std::to_string(line_number));
    }

    return config_file;
}

net::ssl::context getSSLContext(
    const std::string_view key_path,
    const std::string_view cert_path,
    const std::string_view dh_path,
    const std::string_view passphrase)
{
    net::ssl::context ctx(net::ssl::context::tlsv12);

    ctx.set_options(
        net::ssl::context::default_workarounds |
        net::ssl::context::no_sslv2 |
        net::ssl::context::no_sslv3 |
        net::ssl::context::single_dh_use
    );

    ctx.set_password_callback([&passphrase](std::size_t, net::ssl::context_base::password_purpose purpose) {
        if (purpose != net::ssl::context_base::for_reading)
            return std::string();

        return std::string(passphrase);
    });

    try {
        ctx.use_certificate_chain_file(cert_path.data());
        ctx.use_private_key_file(key_path.data(), net::ssl::context::pem);
    } catch (const std::exception& e) {
        std::cerr << "Missing certificate/key file, generate using:\n"
                  << std::format("openssl req -nodes -x509 -newkey rsa:2048 -keyout {} -out {} -days 365\n", key_path, cert_path);
        std::exit(1);
    }

    try {
        ctx.use_tmp_dh_file(dh_path.data());
    } catch (const std::exception& e) {
        std::cerr << "Missing DH params file, generate using:\n"
                  << std::format("openssl dhparam -out {} 2048\n", dh_path);
        std::exit(1);
    }

    return ctx;
}
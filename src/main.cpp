#include <iostream>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/config.hpp>

#include "Startup.hpp"

namespace net = boost::asio;
using tcp = net::ip::tcp;

int main()
{
    auto config_file = readConfigFile();

    const net::ip::address_v4& address = config_file.address;
    const uint16_t& port = config_file.port;

    auto ssl_ctx = getSSLContext(
        config_file.ssl_key_path,
        config_file.ssl_cert_path,
        config_file.ssl_dh_path,
        config_file.ssl_passphrase
    );

    uint thread_count = 1u; // for now

    if (thread_count == 0 || thread_count > std::thread::hardware_concurrency())
        throw_exception(exception_type::unnamed_yet, "Invalid thread count");

    net::io_context ioc{static_cast<int>(thread_count)};
    tcp::acceptor acceptor{ioc, {address, port}};

    std::cout << "Server started on " << address.to_string() << ':' << port << '\n';

    try {
        for (;;){
        tcp::socket socket{ioc};

        acceptor.accept(socket);

        std::thread{
            [ssl_ctx = std::ref(ssl_ctx), socket = std::move(socket)]() mutable
            {
                namespace beast = boost::beast;
                namespace http = beast::http;

                beast::ssl_stream<tcp::socket&> stream{socket, ssl_ctx.get()};

                beast::error_code ec;
                bool close = false;

                stream.handshake(net::ssl::stream_base::server, ec);
                if (ec)
                    throw_exception(exception_type::unnamed_yet, "SSL handshake failed");
                
                beast::flat_buffer buffer;
                http::request<http::string_body> req;
                http::read(stream, buffer, req, ec);
                if (ec)
                    throw_exception(exception_type::unnamed_yet, ec.message());
                http::response<http::string_body> res{http::status::ok, req.version()};

                // Send the response
                http::write(stream, res, ec);
                if (ec)
                    throw_exception(exception_type::unnamed_yet, "HTTP write failed");
            }
        }.detach();
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << '\n';
        exit(EXIT_FAILURE);
    }
}
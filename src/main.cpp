#include <iostream>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/config.hpp>

#include "Startup.hpp"
#include "Listener.hpp"
#include "Session.hpp"
#include "Exception.hpp"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

int main()
{
    auto config_file = readConfigFile();

    const net::ip::address_v4& address = config_file.address;
    const uint16_t& port = config_file.port;

    net::ssl::context ssl_ctx = getSSLContext(
        config_file.ssl_key_path,
        config_file.ssl_cert_path,
        config_file.ssl_dh_path,
        config_file.ssl_passphrase
    );

    uint thread_count = 4u; // for now

    if (thread_count == 0 || thread_count > std::thread::hardware_concurrency())
        throw_exception(exception_type::unnamed_yet, "Invalid thread count");

    net::io_context ioc{static_cast<int>(thread_count)};

    std::shared_ptr<std::string const> doc_root =
        std::make_shared<std::string>(config_file.document_root);

    std::make_shared<Listener>(
        ioc,
        ssl_ctx,
        tcp::endpoint{address, port},
        doc_root
    )->run();

    std::vector<std::thread> v;
    v.reserve(thread_count - 1);

    for (uint i = 0; i < thread_count - 1; i++)
    {
        v.emplace_back([&ioc](){
            ioc.run();
        });
    }

    ioc.run();

    return EXIT_SUCCESS;
}

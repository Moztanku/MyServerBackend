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
namespace beast = boost::beast;

using tcp = net::ip::tcp;

class Session : public std::enable_shared_from_this<Session>
{
    public:
        explicit Session(
            tcp::socket&& socket,
            net::ssl::context& ctx) : m_stream{std::move(socket), ctx}
        {}

        void run()
        {
            // Time out after 30 seconds
            beast::get_lowest_layer(m_stream).expires_after(std::chrono::seconds(30));

            // Perform the SSL handshake
            m_stream.async_handshake(
                net::ssl::stream_base::server,
                beast::bind_front_handler(
                    &Session::on_handshake,
                    shared_from_this()
                )
            );
        }
    private:
        beast::ssl_stream<beast::tcp_stream> m_stream;

        void on_handshake(beast::error_code ec)
        {
            if (ec)
                throw_exception(exception_type::unnamed_yet, ec.message());

            do_read();
        }

        void do_read()
        {
        }

};

class Listener : public std::enable_shared_from_this<Listener>
{
    public:
        Listener(
            net::io_context& ioc,
            net::ssl::context& ctx,
            tcp::endpoint endpoint) : m_ioc{ioc}, m_ctx{ctx}, m_acceptor{ioc}
        {
            beast::error_code ec;

            // Open the acceptor
            m_acceptor.open(endpoint.protocol(), ec);
            if (ec)
                throw_exception(exception_type::unnamed_yet, ec.message());

            // Allow address reuse
            m_acceptor.set_option(net::socket_base::reuse_address(true), ec);
            if (ec)
                throw_exception(exception_type::unnamed_yet, ec.message());

            // Bind to the server address
            m_acceptor.bind(endpoint, ec);
            if (ec)
                throw_exception(exception_type::unnamed_yet, ec.message());

            // Start listening for connections
            m_acceptor.listen(net::socket_base::max_listen_connections, ec);
            if (ec)
                throw_exception(exception_type::unnamed_yet, ec.message());
        }

        void run()
        {
            if (!m_acceptor.is_open())
                return;

            do_accept();
        }

    private:
        net::io_context& m_ioc;
        net::ssl::context& m_ctx;
        tcp::acceptor m_acceptor;

        void do_accept()
        {
            m_acceptor.async_accept(
                net::make_strand(m_ioc),
                beast::bind_front_handler(
                    &Listener::on_accept,
                    shared_from_this()
                )
            );
        }

        void on_accept(beast::error_code ec, tcp::socket socket)
        {
            if (ec)
                throw_exception(exception_type::unnamed_yet, ec.message());

            std::make_shared<Session>(
                 std::move(socket), m_ctx
            )->run();

            do_accept();
        }

};

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
    // tcp::acceptor acceptor{ioc, {address, port}};

    std::cout << "Server started on " << address.to_string() << ':' << port << '\n';

    std::vector<std::thread> threads;
    threads.reserve(thread_count - 1); // running one thread in main as well

    std::shared_ptr<Listener> listener =
        std::make_shared<Listener>(ioc, ssl_ctx, tcp::endpoint{address, port});
    listener->run();

    for (uint i = 0; i < thread_count - 1; i++)
    {
        threads.emplace_back([&ioc](){
            ioc.run();
        });
    }

    ioc.run();

    return EXIT_SUCCESS;
}
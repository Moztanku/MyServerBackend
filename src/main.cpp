#include "Startup.hpp"

int main()
{
    auto config_file = readConfigFile();

    auto ssl_ctx = getSSLContext(
        config_file.ssl_key_path,
        config_file.ssl_cert_path,
        config_file.ssl_dh_path,
        config_file.ssl_passphrase
    );

}
### MyServerBackend

`cmake -S . -B build && cmake --build build && ./build/MyServerBackend`

`openssl req -nodes -x509 -newkey rsa:2048 -keyout ssl/ssl.key -out ssl/ssl.crt -days 365`

`openssl dhparam -out ssl/ssl.dhparams.tst 2048`

# PBKDF2

https://datatracker.ietf.org/doc/html/rfc6070


# pbkdf2.pl 

    $ cpanm PBKDF2::Tiny

    $ perl pbkdf2.pl justfortest b698314b0d68bcbd 2048 32 SHA-256
    password: justfortest
    salt_hexstr: b698314b0d68bcbd
    iter: 2048
    dk_len: 32
    hash: SHA-256
    dk: 7c6d326818ebbfa6235ed3e63d9615b9d064b4a0006fde6c45a2c738c363b53a


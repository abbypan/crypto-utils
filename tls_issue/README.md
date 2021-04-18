# tls issue

# nginx

    $ sudo systemctl start nginx.service

## one-way auth

    $ curl -vv --cacert /etc/self_defined_cert/server_root.cert.pem https://www.example.com


      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
      0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0*   Trying 127.0.0.1:443...
    * Connected to www.example.com (127.0.0.1) port 443 (#0)
    * ALPN, offering h2
    * ALPN, offering http/1.1
    * successfully set certificate verify locations:
    *  CAfile: /etc/self_defined_cert/server_root.cert.pem
    *  CApath: none
    } [5 bytes data]
    * TLSv1.3 (OUT), TLS handshake, Client hello (1):
    } [512 bytes data]
    * TLSv1.3 (IN), TLS handshake, Server hello (2):
    { [122 bytes data]
    * TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
    { [25 bytes data]
    * TLSv1.3 (IN), TLS handshake, Certificate (11):
    { [2026 bytes data]
    * TLSv1.3 (IN), TLS handshake, CERT verify (15):
    { [80 bytes data]
    * TLSv1.3 (IN), TLS handshake, Finished (20):
    { [52 bytes data]
    * TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
    } [1 bytes data]
    * TLSv1.3 (OUT), TLS handshake, Finished (20):
    } [52 bytes data]
    * SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
    * ALPN, server accepted to use http/1.1
    * Server certificate:
    *  subject: C=CN; ST=Anhui; L=Hefei; O=USTC; OU=Cybersecurity; emailAddress=pump@example.com; CN=www.example.com
    *  start date: Oct 17 19:12:16 2020 GMT
    *  expire date: Nov  2 19:12:16 2023 GMT
    *  subjectAltName: host "www.example.com" matched cert's "www.example.com"
    *  issuer: C=CN; ST=Anhui; L=Hefei; O=USTC; OU=Cybersecurity; emailAddress=infosec@example.com; CN=Infosec Server Intermediate
    *  SSL certificate verify ok.
    } [5 bytes data]
    > GET / HTTP/1.1
    > Host: www.example.com
    > User-Agent: curl/7.73.0
    > Accept: */*
    > 
    { [5 bytes data]
    * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
    { [281 bytes data]
    * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
    { [265 bytes data]
    * old SSL session ID is stale, removing
    { [5 bytes data]
    * Mark bundle as not supporting multiuse
    < HTTP/1.1 200 OK
    < Server: nginx/1.18.0
    < Date: Sun, 18 Oct 2020 14:07:25 GMT
    < Content-Type: text/html
    < Content-Length: 49
    < Last-Modified: Sat, 17 Oct 2020 16:17:01 GMT
    < Connection: keep-alive
    < ETag: "5f8b18fd-31"
    < Accept-Ranges: bytes
    < 
    { [49 bytes data]
    100    49  100    49    0     0  16333      0 --:--:-- --:--:-- --:--:-- 16333
    * Connection #0 to host www.example.com left intact
    <html>
        <body>
            just for test
        </body>
    </html>


## two-way auth

    $ curl -vv --cacert /etc/self_defined_cert/server_root.cert.pem --cert /etc/self_defined_cert/client_ee.cert.pem --key /etc/self_defined_cert/client_ee.priv.pem https://bbb.example.com

    
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
      0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0*   Trying 127.0.0.1:443...
    * Connected to bbb.example.com (127.0.0.1) port 443 (#0)
    * ALPN, offering h2
    * ALPN, offering http/1.1
    * successfully set certificate verify locations:
    *  CAfile: /etc/self_defined_cert/server_root.cert.pem
    *  CApath: none
    } [5 bytes data]
    * TLSv1.3 (OUT), TLS handshake, Client hello (1):
    } [512 bytes data]
    * TLSv1.3 (IN), TLS handshake, Server hello (2):
    { [122 bytes data]
    * TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
    { [25 bytes data]
    * TLSv1.3 (IN), TLS handshake, Request CERT (13):
    { [368 bytes data]
    * TLSv1.3 (IN), TLS handshake, Certificate (11):
    { [2026 bytes data]
    * TLSv1.3 (IN), TLS handshake, CERT verify (15):
    { [78 bytes data]
    * TLSv1.3 (IN), TLS handshake, Finished (20):
    { [52 bytes data]
    * TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
    } [1 bytes data]
    * TLSv1.3 (OUT), TLS handshake, Certificate (11):
    } [705 bytes data]
    * TLSv1.3 (OUT), TLS handshake, CERT verify (15):
    } [79 bytes data]
    * TLSv1.3 (OUT), TLS handshake, Finished (20):
    } [52 bytes data]
    * SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
    * ALPN, server accepted to use http/1.1
    * Server certificate:
    *  subject: C=CN; ST=Anhui; L=Hefei; O=USTC; OU=Cybersecurity; emailAddress=pump@example.com; CN=www.example.com
    *  start date: Oct 17 19:12:16 2020 GMT
    *  expire date: Nov  2 19:12:16 2023 GMT
    *  subjectAltName: host "bbb.example.com" matched cert's "bbb.example.com"
    *  issuer: C=CN; ST=Anhui; L=Hefei; O=USTC; OU=Cybersecurity; emailAddress=infosec@example.com; CN=Infosec Server Intermediate
    *  SSL certificate verify ok.
    } [5 bytes data]
    > GET / HTTP/1.1
    > Host: bbb.example.com
    > User-Agent: curl/7.73.0
    > Accept: */*
    > 
    { [5 bytes data]
    * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
    { [969 bytes data]
    * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
    { [969 bytes data]
    * old SSL session ID is stale, removing
    { [5 bytes data]
    * Mark bundle as not supporting multiuse
    < HTTP/1.1 200 OK
    < Server: nginx/1.18.0
    < Date: Sun, 18 Oct 2020 14:08:05 GMT
    < Content-Type: text/html
    < Content-Length: 49
    < Last-Modified: Sat, 17 Oct 2020 16:17:01 GMT
    < Connection: keep-alive
    < ETag: "5f8b18fd-31"
    < Accept-Ranges: bytes
    < 
    { [49 bytes data]
    100    49  100    49    0     0  12250      0 --:--:-- --:--:-- --:--:-- 12250
    * Connection #0 to host bbb.example.com left intact
    <html>
        <body>
            just for test
        </body>
    </html>


## local ip

    $ curl -vv --cacert /etc/self_defined_cert/ip_ee_cert.pem https://192.168.1.5
    *   Trying 192.168.1.5:443...
    * Connected to 192.168.1.5 (192.168.1.5) port 443 (#0)
    * ALPN, offering h2
    * ALPN, offering http/1.1
    * successfully set certificate verify locations:
    *  CAfile: /etc/self_defined_cert/ip_ee_cert.pem
    *  CApath: none
    * TLSv1.3 (OUT), TLS handshake, Client hello (1):
    * TLSv1.3 (IN), TLS handshake, Server hello (2):
    * TLSv1.3 (IN), TLS handshake, Encrypted Extensions (8):
    * TLSv1.3 (IN), TLS handshake, Certificate (11):
    * TLSv1.3 (IN), TLS handshake, CERT verify (15):
    * TLSv1.3 (IN), TLS handshake, Finished (20):
    * TLSv1.3 (OUT), TLS change cipher, Change cipher spec (1):
    * TLSv1.3 (OUT), TLS handshake, Finished (20):
    * SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
    * ALPN, server accepted to use http/1.1
    * Server certificate:
    *  subject: C=CN; ST=Anhui; L=Hefei; O=USTC; OU=Cybersecurity; emailAddress=pump@example.com; CN=192.168.1.5
    *  start date: Apr 18 17:06:24 2021 GMT
    *  expire date: Jun  3 17:06:24 2030 GMT
    *  common name: 192.168.1.5 (matched)
    *  issuer: C=CN; ST=Anhui; L=Hefei; O=USTC; OU=Cybersecurity; emailAddress=pump@example.com; CN=192.168.1.5
    *  SSL certificate verify ok.
    > GET / HTTP/1.1
    > Host: 192.168.1.5
    > User-Agent: curl/7.73.0
    > Accept: */*
    > 
    * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
    * TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
    * old SSL session ID is stale, removing
    * Mark bundle as not supporting multiuse
    < HTTP/1.1 200 OK
    < Server: nginx/1.18.0
    < Date: Sun, 18 Apr 2021 17:08:34 GMT
    < Content-Type: text/html
    < Content-Length: 49
    < Last-Modified: Sat, 17 Oct 2020 16:17:01 GMT
    < Connection: keep-alive
    < ETag: "5f8b18fd-31"
    < Accept-Ranges: bytes
    < 
    <html>
    <body>
    just for test
    </body>
    </html>

    * Connection #0 to host 192.168.1.5 left intact


# okhttp

    $ cd okhttp
    $ gradle run


	> Task :run


	 OneWayAuth: 22:10:15.217, www.example.com


	<html>
			<body>
					just for test
			</body>
	</html>




	 TwoWayAuth: 22:10:15.484, bbb.example.com


	<html>
			<body>
					just for test
			</body>
	</html>



	Deprecated Gradle features were used in this build, making it incompatible with Gradle 7.0.
	Use '--warning-mode all' to show the individual deprecation warnings.
	See https://docs.gradle.org/6.6.1/userguide/command_line_interface.html#sec:command_line_warnings

	BUILD SUCCESSFUL in 728ms
	2 actionable tasks: 1 executed, 1 up-to-date


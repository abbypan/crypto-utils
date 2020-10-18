package hello;

import java.lang.String;
import java.io.IOException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import java.security.cert.X509Certificate;
import okhttp3.Headers;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.tls.Certificates;
import okhttp3.tls.HandshakeCertificates;

public class OneWayAuth {

    String readFile(String filename) {
        File f = new File(filename);
        try {
            byte[] bytes = Files.readAllBytes(f.toPath());
            return new String(bytes,"UTF-8");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "";
    }
;

    X509Certificate selfDefinedServerCertificateAuthority = Certificates.decodeCertificatePem(
            readFile("/etc/self_defined_cert/server_root.cert.pem")
            );

    private final OkHttpClient client;

    public OneWayAuth() {
        HandshakeCertificates certificates = new HandshakeCertificates.Builder()
            .addTrustedCertificate(selfDefinedServerCertificateAuthority)
            // Uncomment if standard certificates are also required.
            //.addPlatformTrustedCertificates()
            .build();

        client = new OkHttpClient.Builder()
            .sslSocketFactory(certificates.sslSocketFactory(), certificates.trustManager())
            .build();
    }

    public String run(String url) throws IOException {
        Request request = new Request.Builder()
            .url(url)
            .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                Headers responseHeaders = response.headers();
                for (int i = 0; i < responseHeaders.size(); i++) {
                    System.out.println(responseHeaders.name(i) + ": " + responseHeaders.value(i));
                }

                throw new IOException("Unexpected code " + response);
            }

            return response.body().string();
        }
    }

}

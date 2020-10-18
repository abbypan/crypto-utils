package hello;

import java.io.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.String;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*; 
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider.Service;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.*;
import java.security.spec.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import okhttp3.Handshake;
import okhttp3.Headers;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.tls.Certificates;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
//import org.bouncycastle.jce.provider.BouncyCastleProvider; 


public class TwoWayAuth {

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

    //val clientEECert = keyStore.getCertificate(CERTIFICATE_ALIAS) as X509Certificate
    //val publicKey = clientEECert.publicKey
    //val privateKey = getKeyStore().getKey(KEY_ALIAS, null) as PrivateKey
    //val keyPair = KeyPair(publicKey, privateKey)
    //val heldCertificate = HeldCertificate(keyPair, clientEECert)


    private final OkHttpClient client;

    public TwoWayAuth() {

    X509Certificate selfDefinedServerCertificateAuthority = Certificates.decodeCertificatePem( readFile("/etc/self_defined_cert/server_root.cert.pem"));

    X509Certificate clientIntermediateCertificateAuthority = Certificates.decodeCertificatePem( readFile("/etc/self_defined_cert/client_ee.cert_chain.int.pem") );

    String clientEECert =  readFile("/etc/self_defined_cert/client_ee.cert.pem") ; 
    String clientEEPriv = readFile("/etc/self_defined_cert/client_ee.priv.pkcs8.pem") ;
    HeldCertificate heldCertificate = HeldCertificate.decode(clientEEPriv + clientEECert);

        HandshakeCertificates certificates = new HandshakeCertificates.Builder()
            .addTrustedCertificate(selfDefinedServerCertificateAuthority)
            .heldCertificate(heldCertificate, clientIntermediateCertificateAuthority) 
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

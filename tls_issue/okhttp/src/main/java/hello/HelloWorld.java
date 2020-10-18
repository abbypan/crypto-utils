package hello;

import org.joda.time.LocalTime;

import java.io.IOException;

import java.security.cert.X509Certificate;
import okhttp3.Headers;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.tls.Certificates;
import okhttp3.tls.HandshakeCertificates;

import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
//import sun.security.ec.SunEC;

public class HelloWorld {
    public static void main(String[] args) throws IOException {

        LocalTime currentTime = new LocalTime();
        System.out.println("\n\n OneWayAuth: " + currentTime + ", www.example.com\n\n");

        OneWayAuth onewayclient = new OneWayAuth();
        String onewayresponse = onewayclient.run("https://www.example.com");
        System.out.println(onewayresponse);

        LocalTime currentTime2 = new LocalTime();
        System.out.println("\n\n TwoWayAuth: " + currentTime2 + ", bbb.example.com\n\n");


        //for (Provider provider : Security.getProviders()) {
            //System.out.println(provider.getName());
            //for (Service service : provider.getServices()) {
                //if (service.getType().equals("KeyFactory"))
                    //System.out.println("  " + service.getAlgorithm());
            //}
        //}


        TwoWayAuth twowayclient = new TwoWayAuth();
        String twowayresponse = twowayclient.run("https://bbb.example.com");
        System.out.println(twowayresponse);

    }


}

package com.test.vulnerable;

import javax.net.ssl.*;
import java.security.cert.*;
import java.security.*;

/**
 * Insecure TLS Configuration Test Samples
 * Tests: TrustManager that accepts all certs, HostnameVerifier bypass
 */
public class InsecureTlsSamples {

    // 1. TrustManager that trusts all certificates
    public void createInsecureSslContext() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }
        };
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }

    // 2. HostnameVerifier that accepts all hostnames
    public void disableHostnameVerification() {
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
    }

    // 3. SSLv3 usage
    public SSLContext useSslV3() throws Exception {
        return SSLContext.getInstance("SSLv3");
    }

    // 4. TLSv1.0 - deprecated
    public SSLContext useTlsV1() throws Exception {
        return SSLContext.getInstance("TLSv1");
    }
}

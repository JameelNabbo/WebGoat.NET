package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
)

// VULN: InsecureSkipVerify disables TLS certificate verification
func insecureHTTPClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return &http.Client{Transport: tr}
}

// VULN: MinVersion set to TLS 1.0 (deprecated)
func weakTLSServer() *http.Server {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS10,
	}
	return &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
	}
}

// VULN: Insecure cipher suites specified
func insecureCipherSuites() *tls.Config {
	return &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}
}

// VULN: Using insecure client to fetch sensitive data
func fetchWithInsecureClient(url string) (string, error) {
	client := insecureHTTPClient()
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func main() {
	data, _ := fetchWithInsecureClient("https://api.example.com/secrets")
	fmt.Println(data)
}

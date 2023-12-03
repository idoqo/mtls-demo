# What is MTLS?
You’ve probably heard about TLS. It is a security protocol that sits between the transport and application layers (in the TCP/IP model) and essentially encrypts application-layer traffic. This encryption provides a guarantee to the client that:

- The server is who they say they are.
- Its communication with the server is confidential and cannot be spied on by a third party.
- Data received is untouched/unmodified along the way.

The regular TLS achieves all three above with a caveat - it provides no guarantee to the server that the client is who they say they are. As a result, verifying the client is done by the application using techniques like basic authentication (using usernames and passwords), Bearer/Access Tokens, or *mutual TLS*.

## Like TLS, but mutual

Mutual TLS (MTLS for short) is a part of the TLS standard. It extends the regular TLS by demanding a client-to-server authentication in addition to the default server-to-client one. To see how this extension happens, let’s summarily go over the steps involved in a typical TLS interaction (a.k.a a TLS handshake).

- The client initiates the session by sending a “hello message containing information like the TLS versions it supports, supported ciphers, a random string of bytes called the *client random* that is later used to generate the encryption key, etc.
- The server responds to the “client hello” with a message containing the cipher and TLS version selected from the list provided by the client. It also presents its certificate to the client for verification.
- The client then verifies the server certificate and encrypts the session key using the public key extracted from the server’s certificate. That way, only the server can decrypt it with its private key.
- Client and server exchange information over the secured connection.

To verify the client identity, MTLS adds a few extra steps before completing the handshake

- The client presents its signed certificate to the server.
- The server verifies the client’s certificate and grants access if the certificate is valid.

These steps mean that the server is now aware of the client’s identity. One advantage of this approach over the means of identification/authentication used in regular TLS (e.g basic authentication and tokens) is that client authentication is now independent of the application. This means a client only needs to have and present a valid certificate for it to be authenticated against the server.

Another advantage is that of zero-trust security, i.e no client is trusted by default, and the server can authenticate/identify a client even if it were seeing it for the first time.

## Terminologies

We’d cover some TLS concepts and what they represent in the relationship between TLS and mTLS

- CSR (short for Certificate Signing Request): An encoded file containing an entity’s identity (name, domain name, location, etc) that is presented to a CA for signing. 
- CA (short for Certificate Authority): An entity that is trusted to sign digital certificates by validating the legitimacy of the certificate request. Operating systems and browsers usually come with a pre-included list of “known CAs” that is used for regular TLS. With MTLS, we usually set up our own CA and configure client devices to trust it.
- TLS Handshake: A negotiation between a client and a server to determine how the communication will be encrypted. They verify each other and exchange information like the TLS version and cipher suite to be used, etc during the handshake.
- x509 Certificate: A digital certificate based on the [ITU-T X509 standard](https://en.wikipedia.org/wiki/X.509). 
- OpenSSL: An open-source implementation of the SSL/TLS protocol. It also has an accompanying command-line tool (with the same name) that can be used to generated keys, create CSRs, and identify certificate information.
## How MTLS improves security

While MTLS isn’t a one-stop-shop for all of your application’s security needs, it provides a level of protection against some attack vectors like:

- Man-in-the-middle attacks: Here, an attacker could impersonate the server while communicating with the client (or impersonate the client while communicating with the server). With MTLS, the attacker needs to have to get both a fake server certificate that is trusted by the client and a fake client certificate that is trusted by the server. This is much harder as opposed to regular TLS where they only need to control one end of the communication.
- Impersonation attacks (Phishing and Credential Stuffing): In cases where an attacker already has the client credentials (e.g via phishing or leaked passwords), they still need to obtain a legitimate certificate to be successful.
- Replay attacks: This is a variation of the man-in-the-middle attack where TCP requests are intercepted and maliciously resent (or replayed). MTLS mitigates this by ensuring that requests with no valid certificate associated with it won’t be successful.
## Why use TLS still?

Despite the advantages provided by MTLS, it’s still not nearly as adopted as the regular TLS on the public internet. This is because as more and more users need to be authenticated with the service, operations like certificate management grow in complexity.

Also, regular TLS suffices for most applications on the internet as the server usually does not need to identify the client. For example, when you visit teleport.com, your browser needs to be sure that the server is who it says it is, but the server running teleport.com does not need to identify you specifically since it serves the same website to everyone. This makes incurring the extra overhead of MTLS less attractive for most public services.

## MTLS in your application

MTLS shines in business applications where there is less number of clients, as well as in microservice architectures where we need services to securely communicate with one another. Most programming languages allow you to set up mutual TLS on your backend but that breaks the advantage of abstracting authentication away from your application. An alternative is to hand over the process to a proxy (such as Nginx or Traefik). Below is an outline of setting up an nginx server on Linux to use mTLS.

To get started, create a new folder in `/etc/ssl/certs` (or your preferred location) for the credentials we will be generating and enter into the new folder.
```bash
    $ mkdir -p /etc/ssl/certs/mtls.local
    $ cd /etc/ssl/certs/mtls.local
```
**Generate CA credentials**
Next, create a CA key to be used in signing and validating all future certificates.
```bash
    $ openssl genrsa -out ca.key 4096
```
Generate a new certificate using the key you just created by running the command below and filling the prompt that follows it.
```
    $ openssl req -new -x509 -days 365 -out ca.crt -key ca.key
```
Here’s a break-down of the command options:

- T`he req` subcommand  specifies that this operation is related to CSR management.
- `-new` asks that we want to create a new CSR
- `-x509` generates a self-signed certificate instead of a CSR. We use this since this is for the CA and we don’t need anyone else to sign it.
- `-days` specify the validity of the generated certificate (one year in our case).
- `-out` dictates where the generated certificate will be stored.
- `-key`: The private key used in generating the certificate.

You can find a more detailed explanation of the `openssl`  command and its flags on the [OpenSSL wiki](https://wiki.openssl.org/index.php/Command_Line_Utilities).
**Generate server certificates**
We will then generate the server private key, create a CSR, and sign the same CSR using the CA we created in the previous step.

```bash
    $ openssl genrsa -out server.key 4096
    
    $ openssl req -new -key server.key -out server.csr
    
    $ openssl x509 -req -days 365 -sha256 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 1 -out server.crt
```

**Configure MTLS on nginx**

Now that we have the server credentials, we will create an nginx configuration file that directs nginx to ask for a client’s certificate and proxies its request to port 8000 if the certificate is valid. Create a new nginx configuration named `mtls.local.conf` in `/etc/nginx/sites-available/` with the configuration below:

```nginx
server {
        # Listen on the default SSL port (443).
    
        listen 443 ssl;
    
        # Sets the server name
        server_name mtls.local;
    
        # The certificate to be presented to clients during a TLS handshake
        ssl_certificate /etc/ssl/certs/mtls.local/server.crt;
        ssl_certificate_key /etc/ssl/certs/mtls.local/server.key;
    
        # Enable mutual TLS (i.e., require clients to present their own certificate)
        ssl_verify_client on;
        # CA that is used to validate client certificates. Can also be a list of supported
        # CAs. See http://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_client_certificate
        ssl_client_certificate /etc/ssl/certs/mtls.local/ca.crt;
    
        # depth of the client certificate chain. See https://cheapsslsecurity.com/p/what-is-ssl-certificate-chain/
        ssl_verify_depth 2;
    
        error_log /var/log/nginx/error.log debug;
    
        keepalive_timeout 10;
        ssl_session_timeout 5m;
    
        location / {
            proxy_pass http://localhost:8000/;
        }
}
```

Test and enable the configuration by running:

```bash
    $ sudo ln -s /etc/nginx/sites-available/mtls.local.conf /etc/nginx/sites-available/
    
    $ sudo nginx -t
    
    $ sudo nginx -s reload
```
**Example application server**
We also need an application running on port 8000. For this example, it is a barebone Go application that responds with the sacred text: “Hello, World”.

```go
    //main.go
    package main
    
    import (
            "fmt"
            "log"
            "net/http"
    )
    
    func main() {
            http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                    fmt.Fprintf(w, "Hello World\n")
            })
    
            log.Fatal(http.ListenAndServe(":8000", nil))
    }
```

**Generate client credentials**
Next, we need to generate valid client certificates in the same way we did for the server earlier. In the `/etc/ssl/certs/mtls.local` directory, generate the client key file and CSR with:

```bash
    $ openssl genrsa -out client.key 4096
    $ openssl req -new -key client.key -out client.csr
```
Sign the client CSR with the same CA we created earlier.
```bash
    $ openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 1 -out client.crt
```
How you install/use the generated custom client certificate we just created depends on the client. To use it with Google Chrome for instance, you would 

- Export `client.crt`  to a PKCS#12 file by running:
 ```bash
    $ openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt -certfile ca.crt
```

- Import the generated `client.pfx` file as a custom certificate i.e., **Settings** > **Security** > **Manage Certificates** > **Your Certificates** > **Import**.

Here, we will simply make an HTTP request with curl while specifying the certificate files. 
Remember to start the Go application (if it is not running already) with `go run main.go` .

```bash
$ curl --cert client.crt --key client.key --cacert ca.crt https://mtls.local
```

We pass in the client certificate and key with the `--cert` and `--key` flags respectively. We’ve also specified the CA certificate file to help curl verify the certificate that will be presented by the server.

## Conclusion

MTLS has been gaining more adoption with the rising popularity of microservices and cloud-native applications. For example, it is used in Kubernetes by service meshes to identify services in the cluster, authorize service-to-service communications, and encrypt the traffic between these services.

In typical applications, it is usually a tradeoff between convenience and security. Nevertheless, it can greatly enhance your application’s security when done right.


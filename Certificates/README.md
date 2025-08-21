Certificates created for this thesis. I created a custom certificate authority (signed by itself), which signed certificates for both the device and the token. Both device and token check certificates they receive during runtime, to see if they are signed by this CA.

For the device, its .crt file was converted to use DER encoding, and the encoding was stored within utilProgram.c. This allows for the device to easily send its certificate over to the token. The device uses OpenSSL for all certificate related work.

For the token, I DER encoded and stored the token's .crt certificate, its private key and the CA's certificate. The token can then easily send its certificate over to the device. It also works with these certificates using wolfSSL.

One of many potential improvements for this thesis includes not having DER encoded certificates directly included within the source code, but to source them from somewhere else (internal storage, TPM, etc.).

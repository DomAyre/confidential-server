# Encryption Wrapper

This is a tool which wraps the python [pyca/cryptography package](https://cryptography.io/en/latest/) with a simple interface to support working with services such as [Confidential Server](https://github.com/DomAyre/confidential-server).

The tool provides the following interface:
- Generate a public/private key pair
- Format the public key for sending to a server
- Parse a formatted public key on the server
- Encrypt data for sending to a client
- Decrypting data recieved from a server

# Encryption Wrapper

This is a tool which wraps the python [pyca/cryptography package](https://cryptography.io/en/latest/) with a simple interface to support working with services such as [Confidential Server](https://github.com/DomAyre/confidential-server).

The tool provides the following interface:
- Generate a public/private RSA key pair ([src/generate_keys.py](src/generate_keys.py))
- Format the public key for sending to a server ([src/public_key_to_b64.py](src/public_key_to_b64.py))
- Parse a formatted public key on the server ([src/lib/b64_to_public_key.py](src/lib/b64_to_public_key.py))
- Encrypt data for sending to a client ([src/encrypt.py](src/encrypt.py))
- Decrypting data recieved from a server ([src/decrypt.py](src/decrypt.py))

## Encryption Scheme

The tool uses hybrid encryption to allow both encryption of large payloads and having encryption only public keys for sending over a network.

- When encrypting with the public RSA key:

  - A symmetric AES-GCM key is generated
  - The payload is encrypted using the AES-GCM key
  - The AES-GCM key is itself encrypted with the RSA public key
  - The result is the encrypted AES-GCM key and the encrypted payload

- When decrypting:

  - The AES-GCM key is decryped with the RSA private key
  - The encrypted payload is then decrypted with the AES-GCM key
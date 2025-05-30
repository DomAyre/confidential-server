# Confidential Server

[![CI](https://github.com/DomAyre/confidential-server/actions/workflows/ci.yml/badge.svg?event=push)](https://github.com/DomAyre/confidential-server/actions/workflows/ci.yml)

- [Overview](#overview)
- [Technologies](#technologies)
- [Usage](#usage)
- [Trust Model](#trust-model)
- [Contributing](#contributing)
  - [Testing](#testing)

## Overview

This server protects data served by cryptographically verifying clients are running exactly a docker container that is trusted. This allows you to serve sensitive data to cloud based compute without having to trust the cloud operator.

## Technologies

Users must be able to easily understand the server code in order to trust it, therefore its based on widely used technologies:

- Server
  - Written as a [python](https://www.python.org) package
  - The server is implemented with [Flask](https://flask.palletsprojects.com/en/stable/)
- Clients - [docker](https://www.docker.com) containers running on [confidential Azure container instances](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-confidential-overview)
- [Encryption Wrapper](tools/encryption_wrapper/readme.md)
  - Uses hybrid encryption to allow large amount of data to be wrapped by a public key.
  - Based on [pyca/cryptography](https://cryptography.io/en/latest/).
  - Off the shelf hybrid encryption tools such as [Tink](https://developers.google.com/tink) were considered, but this custom solution keeps the implementation minimal and therefore the trusted computing base (TCB) as small as possible.
- [C-ACI-Attestation](tools/c-aci-attestation/readme.md)
  - Library for fetching and verifying attestation from Confidential ACI.
  - Core written in C, with bindings for different use cases, we use the python binding.

## Usage

Start the server locally

```
python src/server/run.py \
  --config examples/config/single_file_single_dir_single_policy.yml
```

Generate a public/private key pair for wrapping the server response

```
python tools/encryption_wrapper/src/generate_keys.py
```

Call the `/fetch` endpoint followed by a path which must match a path in your config.

```
curl \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "attestation": "'$(python3 -m attestation.get_attestation_ccf | base64 -w 0)'",
    "wrapping_key": "'$(python tools/encryption_wrapper/src/public_key_to_b64.py)'"
  }' \
  http://localhost:5000/fetch/readme.md \
    | xargs -0 python tools/encryption_wrapper/src/decrypt.py
```

Call `/fetch` for a directory and unzip it

```
curl \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "attestation": "'$(python3 -m attestation.get_attestation_ccf | base64 -w 0)'",
    "wrapping_key": "'$(python tools/encryption_wrapper/src/public_key_to_b64.py)'"
  }' \
  http://localhost:5000/fetch/examples \
  | xargs -0 python tools/encryption_wrapper/src/decrypt.py \
    --out examples.zip
unzip examples.zip
```

You can also run example client containers

```
docker build -t logger-client -f examples/clients/logger.Dockerfile .
docker run --net=host logger-client
```

## Trust Model

Clients of confidential server must be running on an [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html) trusted execution environment or TEE.

The utility VM, or UVM, which runs the containers is running inside the TEE which means all of it's data is encrypted and unavailable to the host.

On Confidential ACI, the container runtime enforces a security policy, which determines what the UVM can and cannot ask of the container.

The AMD SEV-SNP hardware includes a component which produces an attestation, in order to trust it confidential server verifies:

- The report is from genuine AMD SEV-SNP hardware.
- The report comes from a UVM which has a measurement either:
  - Endorsed by Microsoft
  - Reproducable by building from source for independent auditing.
- The report comes from a UVM which is enforcing a security policy that we have explicitly trusted.

If all of these conditions are satisfied, we can be confident the client is running exactly the code we have explicitly trusted.

In order to protect from spoofing, it's vital to only trust security policies relating to containers who will only ever present attestation reports to your server. Otherwise attackers can get attestation reports outside of the normal workflow and use them to get the data in environments other than the intended environments.

## Contributing

All development dependencies are defined in [devcontainer.json](.devcontainer/devcontainer.json).

See the [Development Containers](https://containers.dev) documentation for details of how to use it, either locally or via a hosted runner such as [Github Codespaces](https://github.com/features/codespaces).

### Testing

All tests are based on [pytest](https://pytest.org). To run all tests, simply run

```
pytest
```

### Linting

Linting is done with [ruff](https://github.com/astral-sh/ruff)

```
ruff check . --exclude tools/
```

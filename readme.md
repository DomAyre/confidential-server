# Confidential Server

[![CI](https://github.com/DomAyre/confidential-server/actions/workflows/ci.yml/badge.svg?event=push)](https://github.com/DomAyre/confidential-server/actions/workflows/ci.yml)

- [Overview](#overview)
- [Technologies](#technologies)
- [Trust Model](#trust-model)
- [Contributing](#contributing)
  - [Testing](#testing)

## Overview

This server protects data served by cryptographically verifying clients are running exactly a docker container that is trusted. This allows you to serve sensitive data to cloud based compute without having to trust the cloud operator.

## Technologies

Users must be able to easily understand the server code in order to trust it, therefore its based on widely used technologies:

- Server - written as a [python](https://www.python.org) package
- Clients - [docker](https://www.docker.com) containers running on [confidential Azure container instances](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-confidential-overview)

## Trust Model

Clients of confidential server must be running on an [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html) trusted execution environment or TEE.

The utility VM, or UVM, which runs the containers is running inside the TEE which means all of it's data is encrypted and unavailable to the host.

On Confidential ACI, the container runtime enforces a security policy, which determines what the UVM can and cannot ask of the container.

The AMD SEV-SNP hardware includes a component which produces an attestation report, in order to trust it confidential server verifies:

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

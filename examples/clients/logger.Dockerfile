ARG BASE_IMAGE=python:3.12-bullseye
FROM ${BASE_IMAGE}
ARG CONF_SERVER_URL="http://localhost:5000"

# Install curl
RUN apt-get update && apt-get install -y curl

# Install the wrappying_key tool
COPY tools/encryption_wrapper/requirements.txt /usr/local/bin/encryption_wrapper/requirements.txt
RUN pip install -r /usr/local/bin/encryption_wrapper/requirements.txt
COPY tools/encryption_wrapper /usr/local/bin/encryption_wrapper
RUN chmod +x -R /usr/local/bin/encryption_wrapper

# Install the attestation package
COPY tools/c-aci-attestation/ /src/c-aci-attestation
RUN make -C /src/c-aci-attestation python

ENV CONF_SERVER_URL=${CONF_SERVER_URL}
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/usr/local/bin/"
CMD ["/bin/bash", "-c", " \
    python3 /usr/local/bin/encryption_wrapper/src/generate_keys.py && \
    curl \
        -X POST \
        -H \"Content-Type: application/json\" \
        -d \"{ \
            \\\"attestation\\\":\\\"$(python3 -m attestation.get_attestation_ccf | base64 -w 0)\\\", \
            \\\"wrapping_key\\\":\\\"$(python3 /usr/local/bin/encryption_wrapper/src/public_key_to_b64.py)\\\" \
        }\" \
        ${CONF_SERVER_URL}/fetch/readme.md \
    | xargs -0 python /usr/local/bin/encryption_wrapper/src/decrypt.py \
"]
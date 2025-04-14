ARG BASE_IMAGE=python:3.12-bullseye
FROM ${BASE_IMAGE}
ARG CONF_SERVER_URL="http://localhost:5000"

# Install curl
RUN apt-get update && apt-get install -y curl

# Install the wrappying_key tool
COPY tools/encryption_wrapper /usr/local/bin/encryption_wrapper
RUN pip install -r /usr/local/bin/encryption_wrapper/requirements.txt
RUN chmod +x -R /usr/local/bin/encryption_wrapper

ENV CONF_SERVER_URL=${CONF_SERVER_URL}
ENV PATH="/opt/venv/bin:$PATH"
CMD ["/bin/bash", "-c", " \
    python3 /usr/local/bin/encryption_wrapper/src/generate_keys.py && \
    curl \
        -X POST \
        -H \"Content-Type: application/json\" \
        -d \"{\\\"wrapping_key\\\":\\\"$(python3 /usr/local/bin/encryption_wrapper/src/format_public_key.py)\\\"}\" \
        ${CONF_SERVER_URL}/fetch/readme.md \
"]
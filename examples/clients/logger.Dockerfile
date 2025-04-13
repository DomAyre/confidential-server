ARG BASE_IMAGE=python:3.12-bullseye
FROM ${BASE_IMAGE}
ARG CONF_SERVER_URL="http://localhost:5000"

# Install curl
RUN apt-get update && apt-get install -y curl

# Install python dependencies
COPY tools/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# Install the wrappying_key tool
COPY tools/wrapping_key.py /usr/local/bin/wrapping_key.py
RUN chmod +x /usr/local/bin/wrapping_key.py

ENV CONF_SERVER_URL=${CONF_SERVER_URL}
ENV PATH="/opt/venv/bin:$PATH"
CMD ["/bin/bash", "-c", " \
    python3 /usr/local/bin/wrapping_key.py && \
    curl \
        -X POST \
        -H \"Content-Type: application/json\" \
        -d \"{\\\"wrapping_key\\\":\\\"$(cat public_key.pem | base64 -w 0)\\\"}\" \
        ${CONF_SERVER_URL}/fetch/readme.md \
"]
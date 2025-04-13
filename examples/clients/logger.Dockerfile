ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}
ARG CONF_SERVER_URL="http://localhost:5000"
RUN apt-get update && apt-get install -y curl
ENV CONF_SERVER_URL=${CONF_SERVER_URL}
CMD ["/bin/bash", "-c", "\
    curl -o /tmp/readme.md ${CONF_SERVER_URL}/fetch/readme.md && \
    cat /tmp/readme.md \
"]
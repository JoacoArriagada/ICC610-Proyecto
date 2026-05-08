FROM python:3.11-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y curl git ca-certificates gnupg unzip && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
RUN apt-get update && apt-get install -y nodejs && rm -rf /var/lib/apt/lists/*

# Install CodeQL CLI
RUN curl -L -o /tmp/codeql.zip https://github.com/github/codeql-cli-binaries/releases/download/v2.25.3/codeql-linux64.zip \
    && unzip /tmp/codeql.zip -d /opt \
    && rm /tmp/codeql.zip
ENV PATH="/opt/codeql:${PATH}"

# Download updated CodeQL query packs (Python, JavaScript, Java)
RUN codeql pack download codeql/python-queries codeql/javascript-queries codeql/java-queries

# Install Syft using official installation script
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Grype using official installation script
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Crear usuario para evitar "I have no name!" en la terminal
ARG USERNAME=appuser
ARG USER_UID=1000
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME -s /bin/bash

WORKDIR /workspace

# Iniciar servidor HTTP al ejecutar el contenedor
CMD ["python", "-m", "http.server", "8080"]
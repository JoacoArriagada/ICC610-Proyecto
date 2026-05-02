FROM python:3.11-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y curl git ca-certificates gnupg && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
RUN apt-get update && apt-get install -y nodejs && rm -rf /var/lib/apt/lists/*
RUN curl -L -o /tmp/codeql.zip https://github.com/github/codeql-cli-binaries/releases/download/v2.20.3/codeql-linux64.zip
RUN apt-get update && apt-get install -y unzip && rm -rf /var/lib/apt/lists/*
RUN unzip /tmp/codeql.zip -d /opt && rm /tmp/codeql.zip
ENV PATH="/opt/codeql:${PATH}"
RUN curl -L -o /usr/local/bin/syft https://github.com/anchore/syft/releases/download/v1.12.0/syft_1.12.0_linux_amd64
RUN chmod +x /usr/local/bin/syft
RUN curl -L -o /usr/local/bin/grype https://github.com/anchore/grype/releases/download/v0.82.0/grype_0.82.0_linux_amd64
RUN chmod +x /usr/local/bin/grype
WORKDIR /workspace

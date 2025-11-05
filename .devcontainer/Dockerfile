# Use Ubuntu as base
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-lc"]

# Install system packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-dev \
    build-essential git wget curl ca-certificates \
    nmap xvfb x11vnc fluxbox net-tools socat \
    && rm -rf /var/lib/apt/lists/*

# Install websockify (needed by noVNC)
RUN pip3 install --no-cache-dir websockify

# Install noVNC
RUN git clone https://github.com/novnc/noVNC.git /opt/noVNC && \
    git clone https://github.com/novnc/websockify.git /opt/noVNC/utils/websockify || true

# Create workdir and copy project (project files will be mounted by Codespaces)
WORKDIR /workspaces/pyzenmap

# Install Python deps from requirements.txt if present (Codespaces will mount repo so this will run on build)
COPY requirements.txt /tmp/requirements.txt
RUN if [ -s /tmp/requirements.txt ]; then pip3 install --no-cache-dir -r /tmp/requirements.txt || true; fi

# Make start script executable
COPY start-novnc.sh /usr/local/bin/start-novnc.sh
RUN chmod +x /usr/local/bin/start-novnc.sh

# Expose noVNC port
EXPOSE 6080

# Default command - open a shell. We'll start services manually in Codespace terminal.
CMD [ "bash" ]

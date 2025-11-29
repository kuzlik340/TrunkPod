FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    sudo \
    supervisor \
    openssh-server \
    python3 \
    python3-pip \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash -u 1000 -G sudo admin || true \
 && echo "admin:admin" | chpasswd
RUN mkdir -p /var/run/sshd && ssh-keygen -A
COPY configs/sshd_config /etc/ssh/sshd_config

WORKDIR /app
COPY python_scripts/login_page.py .

COPY supervisor/ /etc/supervisor/conf.d/
COPY supervisord.conf /etc/supervisor/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]

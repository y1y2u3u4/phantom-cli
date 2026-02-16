FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    dante-server \
    iptables \
    passwd \
    && rm -rf /var/lib/apt/lists/*

COPY danted.conf /etc/danted.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY manage-users.sh /usr/local/bin/manage-users.sh

RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/manage-users.sh

# Create log directory for Dante
RUN mkdir -p /var/log/danted && \
    touch /var/log/danted/danted.log

EXPOSE 1080

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

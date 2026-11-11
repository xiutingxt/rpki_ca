FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends rsync \
    && rm -rf /var/lib/apt/lists/*
EXPOSE 873
CMD ["rsync", "--daemon", "--no-detach", "--config=/etc/rsyncd.conf"]

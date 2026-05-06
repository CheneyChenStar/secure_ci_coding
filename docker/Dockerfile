FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc gdb make cmake valgrind \
    python3 python3-pip \
    git curl wget \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /workspace /data/files /etc/securefile

COPY . /workspace
WORKDIR /workspace

RUN make fixed

EXPOSE 9000

CMD ["./build/securefile_server_fixed"]

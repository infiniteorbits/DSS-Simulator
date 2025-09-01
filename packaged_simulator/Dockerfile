FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git automake cmake autoconf libtool g++ coreutils \
    policykit-1 \
    libgtk-3-dev gtk-sharp3 libcanberra-gtk-module libcanberra-gtk3-module \
    at-spi2-core dbus-x11 \
    uml-utilities can-utils iproute2 kmod \
    python3 python3-pip \   
    wget gnupg build-essential sudo screen \
    mono-complete \
  && rm -rf /var/lib/apt/lists/*

RUN wget https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb \
  && dpkg -i /tmp/packages-microsoft-prod.deb \
  && rm /tmp/packages-microsoft-prod.deb \
  && apt-get update \
  && apt-get install -y dotnet-sdk-8.0 \
  && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /app/renode \
  && wget https://dl.antmicro.com/projects/renode/builds/renode-latest.linux-portable.tar.gz -O /tmp/renode-latest.tar.gz \
  && tar xf /tmp/renode-latest.tar.gz -C /app/renode --strip-components=1 \
  && rm /tmp/renode-latest.tar.gz \
  && ln -s /app/renode/renode /usr/local/bin/renode

WORKDIR /app
COPY src ./src
COPY scripts ./scripts
COPY requirements.txt ./requirements.txt
RUN python3 -m pip install --no-cache-dir -r requirements.txt
RUN chmod +x /app/scripts/*.sh

EXPOSE 8090 9000 3335

CMD ["/app/scripts/launch.sh"]


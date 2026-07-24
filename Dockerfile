FROM python:3.12-bookworm@sha256:9bed8554e926c07c6f908841d5ee88c33e8df9236b191526bbce81a9062ab43a

# Update and package installation
RUN apt-get update && \
	apt-get clean && \
	apt-get install -y ca-certificates-java --no-install-recommends && \
	apt-get install -y openjdk-17-jdk p11-kit wkhtmltopdf libqt5gui5 wget unzip && \
	apt-get clean && \
	update-ca-certificates -f

# Get JADX Tool
ENV JADX_VERSION 1.5.5

RUN \
    wget -q "https://github.com/skylot/jadx/releases/download/v$JADX_VERSION/jadx-$JADX_VERSION.zip" -O /tmp/jadx.zip && \
    mkdir -p /opt/jadx && \
    unzip -q /tmp/jadx.zip -d /opt/jadx && \
    chmod 0755 /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui && \
    rm /tmp/jadx.zip

ENV PATH="/opt/jadx/bin:${PATH}"

# Create user
ARG uid=1000
ARG gid=1000
ARG user=app
ARG group=app

RUN groupadd -g ${gid} ${group} \
        && useradd --create-home --home-dir /home/${user} \
            -u ${uid} -g ${group} -s /bin/sh ${user}

ENV HOME=/home/${user}

# Copy entrypoints
COPY entrypoint/web_entrypoint.sh \
    entrypoint/worker_entrypoint.sh /

RUN chown ${uid}:${gid} /web_entrypoint.sh /worker_entrypoint.sh && \
        chmod u+x /web_entrypoint.sh /worker_entrypoint.sh

# Create a directory in the container in /app
RUN mkdir /app
# Copy all to /app directory
COPY . /app

# Use /app as the workdir
WORKDIR /app


# Upgrade pip and install python dependencies
RUN pip install --upgrade pip \
	&& pip install -r requirements.txt

# Encoding configuration
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV PYTHONIOENCODING utf8

# Logs
RUN mkdir -p app/logs
RUN touch app/logs/debug.log

# RabbitMQ directory
RUN mkdir -p rabbitmq/logs

# Set the permissions to the user
RUN chown -R ${uid}:${gid} /app

# Run the container as non-root user
USER ${uid}

# Expose the 8000 port
EXPOSE 8000

FROM python:3.9.16-buster@sha256:5e28891402c02291f65c6652a8abddedcb5af15933e923c07c2670f836243833

# Update and package installation
RUN apt-get update && \
	apt-get clean && \
	apt-get install -y ca-certificates-java --no-install-recommends && \
	apt-get clean

RUN apt-get update && \
	apt-get install -y openjdk-11-jdk p11-kit wkhtmltopdf libqt5gui5 && \
	apt-get install -y  && \
	apt-get clean && \
	update-ca-certificates -f

# Avoid issue in libqt5gui5 #73
RUN strip --remove-section=.note.ABI-tag /usr/lib/x86_64-linux-gnu/libQt5Core.so.5

# Get JADX Tool
ENV JADX_VERSION 1.4.7

RUN \
    wget "https://github.com/skylot/jadx/releases/download/v$JADX_VERSION/jadx-$JADX_VERSION.zip" && \
    unzip "jadx-$JADX_VERSION.zip"

# Create user
ARG uid=1000
ARG gid=1000
ARG user=app
ARG group=app

RUN groupadd -g ${gid} ${group} \
        && useradd -u ${uid} -g ${group} -s /bin/sh ${user}

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

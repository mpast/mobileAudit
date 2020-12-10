FROM python:3.9.0-buster@sha256:8829824d85665db842f33f6a71960b00f3e3b329f297e499e24c748e29ae19f9
# Update and package installation
RUN apt-get update && \
	apt-get clean && \
	apt-get install -y ca-certificates-java --no-install-recommends && \
	apt-get clean

RUN apt-get update && \
	apt-get install -y openjdk-11-jdk p11-kit wkhtmltopdf && \
	apt-get install -y  && \
	apt-get clean && \
	update-ca-certificates -f

# Get JADX Tool
ENV JADX_VERSION 1.1.0

RUN \
    wget "https://github.com/skylot/jadx/releases/download/v$JADX_VERSION/jadx-$JADX_VERSION.zip" && \
    unzip "jadx-$JADX_VERSION.zip"

# Create a directory in the container in /app
RUN mkdir /app

# Copy all to /app directory
COPY . /app

# Use /app as the workdir
WORKDIR /app

# Install python dependencies
RUN pip install -r requirements.txt

# Encoding configuration
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV PYTHONIOENCODING utf8

# Set the permissions to the user
RUN chown -R 1001:1001 /app

# Run the container as 1001 user
USER 1001
# Expose the 8000 port
EXPOSE 8000
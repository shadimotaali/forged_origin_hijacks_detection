# Use the official Python 3.10 slim image as base
FROM python:3.10-slim

# Environment
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 POETRY_VERSION=1.8.2

# Set the working directory
WORKDIR /root/

# Install system dependencies
RUN apt-get update && apt-get install -y curl git zip tmux tcpdump && rm -rf /var/lib/apt/lists/*

# Install Reflex
COPY dashboard/requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy project files into the container
COPY dashboard .

RUN mkdir logs

# Expose the port Reflex will run on
EXPOSE 3001 8001

# Start the Reflex web server
CMD ["bash", "-c", "reflex init && reflex run --env prod --frontend-port 3001 --backend-port 8001"]
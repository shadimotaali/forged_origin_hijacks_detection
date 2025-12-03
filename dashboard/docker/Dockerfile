# Use the official Python 3.10 slim image as base
FROM python:3.10-slim

# Environment
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 POETRY_VERSION=1.8.2

# Install system dependencies
RUN apt-get update && apt-get install -y curl git zip tmux tcpdump && rm -rf /var/lib/apt/lists/*

ARG USERNAME=user
ARG UID=1000
ARG GID=1000

RUN groupadd -g $GID $USERNAME || true
RUN useradd -m -u $UID -g $GID -s /bin/bash $USERNAME || true

RUN mkdir -p /home/$USERNAME
WORKDIR /home/$USERNAME

# Install Reflex
COPY dashboard/requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy project files into the container
COPY dashboard .

RUN mkdir logs

# Expose the port Reflex will run on
EXPOSE 3001 8001

RUN chown -R $UID:$GID /home/$USERNAME

USER $USERNAME

# Start the Reflex web server
CMD ["bash", "-c", "reflex init && reflex run --env prod --frontend-port 3001 --backend-port 8001"]
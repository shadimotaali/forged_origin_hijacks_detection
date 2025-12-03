#!/bin/bash


#### NOW BUILD THE BACKEND ####
# Define the target directory
image_name="dfoh-dashboard-image"

cd ..
docker build --build-arg USERNAME=$(whoami) --build-arg UID=$(id -u) --build-arg GID=$(id -g) --tag=$image_name -f dashboard/docker/Dockerfile .

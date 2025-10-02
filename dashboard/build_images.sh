#!/bin/bash


#### NOW BUILD THE BACKEND ####
# Define the target directory
image_name="dfoh-dashboard-image"

cd ..
docker build --no-cache --tag=$image_name -f dashboard/docker/Dockerfile .

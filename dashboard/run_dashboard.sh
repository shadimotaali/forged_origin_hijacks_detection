#!/bin/bash


docker run -dit --name dfoh-dashboard -p 127.0.0.1:3001:3001 -p 127.0.0.1:8001:8001 dfoh-dashboard-image

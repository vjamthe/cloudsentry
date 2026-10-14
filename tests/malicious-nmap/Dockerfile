FROM node:20-bookworm-slim
RUN npm install -g lodash@4.17.21
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*

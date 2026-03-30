FROM node:trixie-slim AS base
WORKDIR /app
RUN apt-get update \
 && apt-get install -yqq openssl \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p data/ca
COPY ["./package.json", "./package-lock.json", "./"]
EXPOSE 3000 3001

FROM base AS deploy
RUN  ["npm", "ci", "--omit=dev"]
COPY ["./", "./"]
CMD  ["node", "src/index.js"]

FROM base AS dev
RUN  ["npm", "ci"]
COPY ["./", "./"]
CMD  ["npm", "run", "dev"]
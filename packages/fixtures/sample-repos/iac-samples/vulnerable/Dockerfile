FROM node:latest

ARG DB_PASSWORD=SuperSecretPass123
ENV STRIPE_API_KEY=sk_live_abcdefghijklmnopqrstuvwx

ADD https://example.com/installer.sh /tmp/installer.sh
ADD ./config /app/config
ADD release.tar.gz /app/release

WORKDIR /app
COPY package.json .
RUN npm install

CMD ["node", "server.js"]

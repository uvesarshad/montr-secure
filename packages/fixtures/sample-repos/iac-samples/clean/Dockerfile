FROM node:18.20.4-slim@sha256:1111111111111111111111111111111111111111111111111111111111111a

RUN addgroup --system app && adduser --system --ingroup app app
USER app

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .

CMD ["node", "server.js"]

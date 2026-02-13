FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY tsconfig.json ./
COPY src/ ./src/

# Data directories for document pipeline (Tessera v3.1 §6)
RUN mkdir -p /app/data/uploads /app/data/normalized

EXPOSE 3100

CMD ["npx", "tsx", "watch", "src/server.ts"]

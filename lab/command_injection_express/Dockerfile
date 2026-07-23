FROM node:20-slim

WORKDIR /app
COPY package.json .
RUN npm install --omit=dev
COPY app.js .

EXPOSE 5000
CMD ["node", "app.js"]

FROM node:20-alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
ENV NODE_OPTIONS=--max-http-header-size=8192
EXPOSE 3200
CMD ["npm", "start"]

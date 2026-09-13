FROM node:20-alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
EXPOSE 3900 3998 3999 5354 5355 5356
CMD ["npm", "start"]

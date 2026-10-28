# Stage 1: Build the React + Vite frontend using modern LTS Node.js (replacing EOL node:16-alpine)
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npx vite build

# Stage 2: Serve static assets with lightweight Nginx
FROM nginx:1.27-alpine

COPY --from=builder /app/dist /usr/share/nginx/html

RUN printf 'server {\n\
    listen 3000;\n\
    server_name _;\n\
    root /usr/share/nginx/html;\n\
    index index.html;\n\
    add_header X-Content-Type-Options "nosniff" always;\n\
    add_header X-Frame-Options "DENY" always;\n\
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;\n\
    location / {\n\
        try_files $uri $uri/ /index.html;\n\
    }\n\
}\n' > /etc/nginx/conf.d/default.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]

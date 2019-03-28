# STEP 1 build static website
FROM node:alpine as builder
RUN apk update && apk add --no-cache make git
# Create app directory
WORKDIR /app
# Install app dependencies
ADD dockerstack-application/Clients/SPA/ClientApp /app

RUN cd /app && npm set progress=false && npm install
# Copy project files into the docker image

RUN cd /app && npm run build

# STEP 2 build a small nginx image with static website
FROM nginx:alpine
## Remove default nginx website
RUN rm -rf /usr/share/nginx/html/*
## From 'builder' copy website to default nginx public folder
COPY --from=builder /app/dist /usr/share/nginx/html
CMD ["nginx", "-g", "daemon off;"]

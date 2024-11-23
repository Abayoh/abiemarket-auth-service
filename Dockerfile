# Use an official Node.js base image
FROM node:current-alpine3.18 

# Set the working directory inside the container
WORKDIR /app

# Copy the package.json and package-lock.json files
COPY force_change.tx ./
COPY package*.json ./

# Change ownership of the package files
RUN chown -R 1000:1000 /app/package*.json

# Install npm packages
RUN npm install

# Copy the compiled files from the build directory
COPY build/ ./build/

# Copy the config files
#COPY config/ ./config/ #for local development

# Create the log directory and set permissions
RUN mkdir -p /app/log && chown -R 1000:1000 /app/log
RUN mkdir -p /app/config && chown -R 1000:1000 /app/config

# Change ownership of the copied files
RUN chown -R 1000:1000 /app/build /app/config

# Run as User 1000
USER 1000

# Expose the port the app runs on
EXPOSE 80

# Specify the command to run when the container starts
CMD ["npm", "start"]
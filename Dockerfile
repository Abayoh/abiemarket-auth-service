# Use an official Node.js base image
FROM node:current-alpine3.18 

# Set the working directory inside the container
WORKDIR /app

#induced change
COPY forceChange.txt ./

# Copy the package.json and package-lock.json files
COPY package*.json ./

RUN npm install

# Copy the compiled files from the build directory
COPY build/ ./build/

# Run as User 1000
USER 1000

# Expose the port the app runs on
EXPOSE 80

# Specify the command to run when the container starts
CMD ["npm", "start"]

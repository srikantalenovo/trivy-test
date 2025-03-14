# Use an official base image
FROM alpine:3.14

# Set the working directory
WORKDIR /app

# Copy the application files into the container
COPY . .

# Install any necessary dependencies
RUN apk add --no-cache bash

# Define the command to run your application
CMD ["bash"]

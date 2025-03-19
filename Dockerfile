# Use an official base image
FROM alpine:3.14

RUN mkdir -p /sri/src
RUN chmod -R 777 /sri/src
RUN ls -lart && pwd
COPY sri-appone /sri/src/sri-appone
RUN ls -lart /sri/src/
# Set the working directory
WORKDIR /app 

# Copy the application files into the container
COPY . .

# Install any necessary dependencies
RUN apk add --no-cache bash

# Define the command to run your application
CMD ["bash"]

# Use a lightweight base image
FROM openjdk:17-jdk-slim

# Set the working directory
WORKDIR /app

# Copy the built JAR file to the container
ARG JAR_FILE=build/libs/*SNAPSHOT.jar
COPY ${JAR_FILE} app.jar

# Expose the port the app runs on (default for Spring Boot is 8080)
EXPOSE 8090

# Run the JAR file
ENTRYPOINT ["java", "-jar", "/app.jar"]

# Stage 1: Build
FROM gradle:7.6-jdk17 AS build

# Set the working directory in the container
WORKDIR /app

# Copy the Gradle wrapper and build scripts
COPY gradle gradle
COPY gradlew .
COPY build.gradle* settings.gradle* ./
COPY src src

# Build the application
RUN ./gradlew clean build -x test

# Stage 2: Run
FROM openjdk:17-jdk-slim

# Set the working directory in the container
WORKDIR /app

# Copy the executable JAR file from the build stage
COPY --from=build /app/build/libs/*.jar app.jar

# Expose the port the application runs on
EXPOSE 8090

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]

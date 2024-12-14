# Stage 1: Build
FROM gradle:7.6-jdk17 AS build

#ToDO : Make these as runtime args. Store and fetch from Azure KeyVault
# Currently are fetched from GH action secrets
ARG POSTGRES_URL
ARG POSTGRES_USERNAME
ARG POSTGRES_PASSWORD
ARG REDIS_URL
ARG REDIS_PASSWORD

# Set environment variables in the container
ENV POSTGRES_URL=$POSTGRES_URL
ENV POSTGRES_USERNAME=$POSTGRES_USERNAME
ENV POSTGRES_PASSWORD=$POSTGRES_PASSWORD
ENV REDIS_URL=$REDIS_URL
ENV REDIS_PASSWORD=$REDIS_PASSWORD

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
COPY --from=build /app/build/libs/*SNAPSHOT.jar app.jar

# Expose the port the application runs on
EXPOSE 8090

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]

# Use the official OpenJDK 17 image as the base image
FROM openjdk:17-jdk-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the JAR file into the container
COPY target/*.jar app.jar

# Expose the port your Spring Boot app is running on
EXPOSE 8080

# Run the Spring Boot app when the container starts
CMD ["java", "-jar", "app.jar"]
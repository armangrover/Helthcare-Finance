# Use a lightweight OpenJDK image
FROM openjdk:17-jdk-slim

WORKDIR /app

# Copy the built JAR file into the container
COPY healthcare/target/healthcare-tracker-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
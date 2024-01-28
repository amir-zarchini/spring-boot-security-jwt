FROM openjdk:17-jdk-slim
LABEL authors="amir-zr"
WORKDIR /app
VOLUME /tmp
COPY target/*.jar /app/app.jar
ENTRYPOINT ["java","-jar","/app/app.jar"]
FROM openjdk:17-jdk-slim AS build
WORKDIR /app
COPY . .
RUN ./mvnw package

FROM openjdk:17-jdk-slim
ARG VERSION=1.0.0
WORKDIR /app
COPY --from=build /app/target/boot-web-${VERSION}.jar app.jar
CMD ["java", "-jar", "app.jar"]
EXPOSE 8080
EXPOSE 8443

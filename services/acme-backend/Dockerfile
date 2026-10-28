# Acme Support backend (Spring Boot, Java 21). Build from this directory:
#   docker build -t warden/acme-backend:dev services/acme-backend
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
# Resolve dependencies first for layer caching.
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q clean package -DskipTests

FROM eclipse-temurin:24-jre AS runtime
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin acme
WORKDIR /app
COPY --from=build /src/target/acme-support-*.jar app.jar
USER acme
EXPOSE 8081
HEALTHCHECK --interval=10s --timeout=3s --retries=20 \
  CMD ["sh", "-c", "wget -qO- http://127.0.0.1:8081/actuator/health | grep -q UP || exit 1"]
ENTRYPOINT ["java", "-jar", "app.jar"]

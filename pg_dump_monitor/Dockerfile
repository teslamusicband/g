# Используем официальный образ Gradle с JDK
FROM gradle:7.4.2-jdk17-alpine AS builder

# Настройка прокси (передается через --build-arg)
ARG HTTP_PROXY
ARG HTTPS_PROXY
ENV http_proxy=${HTTP_PROXY}
ENV https_proxy=${HTTPS_PROXY}

# Создаем рабочую директорию
WORKDIR /app

# Копируем только файлы для зависимостей сначала
COPY build.gradle.kts settings.gradle.kts gradle.properties /app/
COPY gradle /app/gradle
RUN gradle dependencies --no-daemon

# Копируем исходный код
COPY src /app/src

# Собираем приложение
RUN gradle build --no-daemon

# Финальный образ
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=builder /app/build/libs/*.jar /app/pgdump-monitor.jar

# Убираем прокси из финального образа
ENV http_proxy=
ENV https_proxy=

ENTRYPOINT ["java", "-jar", "/app/pgdump-monitor.jar"]

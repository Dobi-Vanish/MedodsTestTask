# HTTP Server for providing JWT tokens (Go)

[![Go](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-blue.svg)](https://www.postgresql.org/)
[![Docker](https://img.shields.io/badge/Docker-24.0+-blue.svg)](https://www.docker.com/)

Простой HTTP-сервер на Go для генерации, хранения и проверки JWT-токенов.

## 🚀 Функционал
- **JWT-авторизация** (Middleware для некоторых эндпоинтов)
- **API Endpoints**:
  - `GET /refresh/{id}` - обновление токенов
  - `GET /getguid` - предоставление guid пользователя
  - `GET /logout` - разлогинить пользователя
  - `GET /provide/{id}` - предоставление токенов
  - `POST /registrate` - регистрация пользователя
- **Хранилище**: PostgreSQL с миграциями (`goose`)
- **Docker-сборка**: Готовый `docker-compose.yml` для развертывания

## 📦 Установка
### Предварительные требования
- Go 1.21+
- PostgreSQL 15+
- Docker 24.0+

### Запуск локально
1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/Dobi-Vanish/MedodsTestTask
2. Перейдите в папку deployments и запустите через makefile:
   ```bash
   cd auth-service/deployments
   docker-compose -f docker-compose.yml up -d
### Пример успешного запроса
 Запуск коллекции в Postman для проверки:  
 ![изображение](https://github.com/user-attachments/assets/b4c6e18b-37db-42b7-b01d-4f5a07082725)

 ### Примечание
 Для начала необходимо зарегестрировать нового пользователя чтобы было понятно, на какого пользователя сохранять токены в БД.   
 Если есть какие-либо другие замечания - прошу указать, если надо как-либо исправить.


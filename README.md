# Article Management System - Backend

A production-ready RESTful API built with Spring Boot 3.5.7 and Java 21, featuring comprehensive user authentication, article management, email verification, and advanced security measures.

---

## 🎯 Quick Links

<div align="center">

[![Interview Questions](https://img.shields.io/badge/📚_Interview_Questions-Click_Here-blue?style=for-the-badge)](./QUESTIONS.md)
[![API Documentation](https://img.shields.io/badge/📖_API_Docs-Scroll_Down-green?style=for-the-badge)](#-api-endpoints)
[![Setup Guide](https://img.shields.io/badge/🚀_Quick_Setup-Get_Started-orange?style=for-the-badge)](#-installation--setup)

**[View 60+ Interview Questions & Answers →](./QUESTIONS.md)**

</div>

---

## 📋 Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
- [Database Schema](#database-schema)
- [Security Features](#security-features)
- [Email Service](#email-service)
- [Rate Limiting](#rate-limiting)
- [Docker Deployment](#docker-deployment)
- [Testing](#testing)
- [Concepts Strengthened](#concepts-strengthened)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## ✨ Features

### Authentication & Authorization
- ✅ User registration with email verification
- ✅ JWT-based authentication (Access + Refresh tokens)
- ✅ Password reset via email
- ✅ Account lockout after failed login attempts
- ✅ Email verification token expiration
- ✅ Secure password hashing with BCrypt

### Article Management
- ✅ Create, Read, Update, Delete (CRUD) operations
- ✅ Pagination and sorting
- ✅ Full-text search functionality
- ✅ View count tracking
- ✅ Author-based article filtering
- ✅ Article status management (DRAFT, PUBLISHED, ARCHIVED)

### Security & Performance
- ✅ Rate limiting (General + Auth endpoints)
- ✅ CORS configuration
- ✅ Caching with Caffeine
- ✅ Connection pooling (HikariCP)
- ✅ Global exception handling
- ✅ Request validation

### Email Service
- ✅ SendGrid integration
- ✅ Async email sending
- ✅ Retry mechanism for failed emails
- ✅ HTML email templates (Thymeleaf)
- ✅ Email health check endpoint

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|-----------|
| **Backend Framework** | Spring Boot 3.5.7 |
| **Language** | Java 21 |
| **Database** | PostgreSQL |
| **Security** | Spring Security + JWT |
| **ORM** | Spring Data JPA (Hibernate) |
| **Email Service** | SendGrid SMTP |
| **Template Engine** | Thymeleaf |
| **Caching** | Caffeine |
| **Rate Limiting** | Bucket4j |
| **Build Tool** | Maven |
| **Containerization** | Docker |

---

## 📦 Prerequisites

- **Java 21** or higher
- **PostgreSQL 15+** (or use Docker)
- **Maven 3.9+** (or use included Maven Wrapper)
- **SendGrid Account** (for email functionality)
- **Docker** (optional, for containerized deployment)

---

## 🚀 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/ArticleMS-Backend.git
cd ArticleMS-Backend
```

### 2. Create PostgreSQL Database

```sql
CREATE DATABASE articledb;
CREATE USER postgres WITH ENCRYPTED PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE articledb TO postgres;
```

### 3. Configure Environment Variables

Create an `application-local.properties` file in `src/main/resources/`:

```properties
# Database Configuration
PGHOST=localhost
PGPORT=5432
PGDATABASE=articledb
PGUSER=postgres
PGPASSWORD=your_database_password

# JWT Configuration
JWT_SECRET=your-256-bit-secret-key-here-make-it-very-long-and-random

# SendGrid Configuration
SENDGRID_API_KEY=your-sendgrid-api-key
SENDGRID_FROM_EMAIL=noreply@yourdomain.com

# Frontend URL
FRONTEND_URL=http://localhost:3000
```

### 4. Build the Project

Using Maven Wrapper (recommended):
```bash
./mvnw clean install -DskipTests
```

Or using system Maven:
```bash
mvn clean install -DskipTests
```

### 5. Run the Application

```bash
./mvnw spring-boot:run
```

The application will start on `http://localhost:8080`

---

## ⚙️ Configuration

### JWT Configuration

```properties
jwt.access-token-expiration=900000         # 15 minutes
jwt.refresh-token-expiration=604800000     # 7 days
```

### Email Configuration

```properties
app.email.enabled=true
app.email.verification.expiration=86400000  # 24 hours
```

### Rate Limiting

```properties
rate.limit.general=100    # 100 requests per minute
rate.limit.auth=5         # 5 auth requests per minute
```

### Database Connection Pool

```properties
spring.datasource.hikari.maximum-pool-size=10
spring.datasource.hikari.minimum-idle=5
spring.datasource.hikari.connection-timeout=30000
```

---

## 🔌 API Endpoints

### Base URL: `http://localhost:8080/api`

### Authentication Endpoints

#### 1. Register User
```http
POST /auth/register
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "Test@1234"
}
```

**Response (201 Created):**
```json
{
  "message": "Registration successful! Please check your email to verify your account."
}
```

**Password Requirements:**
- Minimum 8 characters
- At least one digit
- At least one lowercase letter
- At least one uppercase letter
- At least one special character (@#$%^&+=)

---

#### 2. Verify Email
```http
GET /auth/verify-email?token={verification_token}
```

**Response (200 OK):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "tokenType": "Bearer",
  "userId": 1,
  "email": "john@example.com",
  "name": "John Doe",
  "message": "Email verified successfully! You are now logged in."
}
```

---

#### 3. Resend Verification Email
```http
POST /auth/resend-verification
Content-Type: application/json

{
  "email": "john@example.com"
}
```

---

#### 4. Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "Test@1234"
}
```

**Response (200 OK):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "tokenType": "Bearer",
  "userId": 1,
  "email": "john@example.com",
  "name": "John Doe"
}
```

---

#### 5. Refresh Token
```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

#### 6. Forgot Password
```http
POST /auth/forgot-password
Content-Type: application/json

{
  "email": "john@example.com"
}
```

---

#### 7. Reset Password
```http
POST /auth/reset-password
Content-Type: application/json

{
  "token": "reset_token_from_email",
  "newPassword": "NewPass@1234"
}
```

---

#### 8. Logout
```http
POST /auth/logout
Authorization: Bearer {access_token}
```

---

### Article Endpoints (Requires Authentication)

#### 1. Get All Articles (Paginated)
```http
GET /articles?page=0&size=10&sortBy=createdAt&sortDir=desc
Authorization: Bearer {access_token}
```

**Query Parameters:**
- `page`: Page number (default: 0)
- `size`: Items per page (default: 10)
- `sortBy`: Field to sort by (default: createdAt)
- `sortDir`: Sort direction - asc/desc (default: desc)

**Response (200 OK):**
```json
{
  "content": [
    {
      "id": 1,
      "title": "Introduction to Spring Boot",
      "content": "Spring Boot is an amazing framework...",
      "authorName": "John Doe",
      "authorId": 1,
      "status": "PUBLISHED",
      "viewCount": 42,
      "createdAt": "2024-11-04 10:30:00",
      "updatedAt": "2024-11-04 15:45:00"
    }
  ],
  "pageable": {
    "pageNumber": 0,
    "pageSize": 10
  },
  "totalElements": 100,
  "totalPages": 10,
  "last": false
}
```

---

#### 2. Search Articles
```http
GET /articles/search?keyword=spring&page=0&size=10
Authorization: Bearer {access_token}
```

---

#### 3. Get Article by ID
```http
GET /articles/{id}
Authorization: Bearer {access_token}
```

**Response (200 OK):**
```json
{
  "id": 1,
  "title": "Introduction to Spring Boot",
  "content": "Spring Boot is an amazing framework that simplifies...",
  "authorName": "John Doe",
  "authorId": 1,
  "status": "PUBLISHED",
  "viewCount": 43,
  "createdAt": "2024-11-04 10:30:00",
  "updatedAt": "2024-11-04 15:45:00"
}
```

---

#### 4. Get My Articles
```http
GET /articles/my?page=0&size=10
Authorization: Bearer {access_token}
```

---

#### 5. Create Article
```http
POST /articles
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "title": "Introduction to Spring Boot",
  "content": "Spring Boot is an amazing framework that simplifies Java development..."
}
```

**Validation Rules:**
- Title: 5-200 characters, required
- Content: Minimum 10 characters, required

**Response (201 Created):**
```json
{
  "id": 1,
  "title": "Introduction to Spring Boot",
  "content": "Spring Boot is an amazing framework...",
  "authorName": "John Doe",
  "authorId": 1,
  "status": "PUBLISHED",
  "viewCount": 0,
  "createdAt": "2024-11-04 10:30:00",
  "updatedAt": null
}
```

---

#### 6. Update Article
```http
PUT /articles/{id}
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "title": "Updated Title",
  "content": "Updated content..."
}
```

**Note:** Only the author can update their article.

---

#### 7. Delete Article
```http
DELETE /articles/{id}
Authorization: Bearer {access_token}
```

**Response (200 OK):**
```json
{
  "message": "Article deleted successfully"
}
```

**Note:** Only the author can delete their article.

---

### Health Check Endpoints

#### Email Service Health
```http
GET /health/email
```

**Response (200 OK):**
```json
{
  "provider": "SendGrid",
  "enabled": true,
  "host": "smtp.sendgrid.net",
  "port": 587,
  "username": "apikey",
  "from": "no***@example.com",
  "status": "ACTIVE",
  "message": "SendGrid email service is configured and active",
  "sendgrid": "Connected",
  "smtpStatus": "Ready"
}
```

---

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    verification_token VARCHAR(255) UNIQUE,
    verification_token_expiry TIMESTAMP,
    password_reset_token VARCHAR(255),
    password_reset_token_expiry TIMESTAMP,
    account_locked BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    lock_time TIMESTAMP,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP,
    last_login TIMESTAMP
);

CREATE INDEX idx_email ON users(email);
CREATE INDEX idx_verification_token ON users(verification_token);
```

### Articles Table
```sql
CREATE TABLE articles (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    content TEXT NOT NULL,
    author_id BIGINT NOT NULL,
    author_name VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PUBLISHED',
    view_count BIGINT DEFAULT 0,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES users(id)
);

CREATE INDEX idx_author_id ON articles(author_id);
CREATE INDEX idx_created_at ON articles(created_at);
```

### Refresh Tokens Table
```sql
CREATE TABLE refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(500) UNIQUE NOT NULL,
    user_id BIGINT UNIQUE NOT NULL,
    expiry_date TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_token ON refresh_tokens(token);
CREATE INDEX idx_user_id ON refresh_tokens(user_id);
```

---

## 🔒 Security Features

### JWT Authentication
- **Access Token:** Short-lived (15 minutes) for API requests
- **Refresh Token:** Long-lived (7 days) for obtaining new access tokens
- **HS256 Algorithm:** HMAC with SHA-256 for token signing

### Password Security
- **BCrypt Hashing:** Industry-standard password hashing
- **Strong Password Policy:** Enforced via validation
- **Password Reset:** Secure token-based reset mechanism

### Account Protection
- **Account Lockout:** After 5 failed login attempts
- **Lock Duration:** 24 hours automatic unlock
- **Email Verification:** Required before account activation

### API Security
- **Rate Limiting:** Prevents abuse
- **CORS:** Configured for specific origins
- **Input Validation:** Bean Validation (Jakarta Validation)
- **SQL Injection Protection:** JPA/Hibernate parameterized queries

---

## 📧 Email Service

### SendGrid Integration

The application uses SendGrid SMTP for reliable email delivery.

#### Email Types:
1. **Verification Email** - Sent on registration
2. **Welcome Email** - Sent after email verification
3. **Password Reset Email** - Sent on password reset request

#### Features:
- **Async Processing** - Non-blocking email sending
- **Retry Mechanism** - 3 attempts with exponential backoff
- **HTML Templates** - Professional Thymeleaf templates
- **Error Handling** - Graceful fallback on failures

#### Configuration:
```properties
spring.mail.host=smtp.sendgrid.net
spring.mail.port=587
spring.mail.username=apikey
spring.mail.password=${SENDGRID_API_KEY}
```

---

## ⚡ Rate Limiting

### Implementation: Bucket4j

#### General Endpoints
- **Limit:** 100 requests per minute per IP
- **Strategy:** Token bucket algorithm

#### Authentication Endpoints
- **Limit:** 5 requests per minute per IP
- **Endpoints:** `/api/auth/login`, `/api/auth/register`

#### Response on Limit Exceeded:
```json
{
  "status": 429,
  "message": "Too many requests. Please try again later.",
  "timestamp": "2024-11-04T10:30:00",
  "path": "uri=/api/articles"
}
```

---

## 🐳 Docker Deployment

### Build Docker Image

```bash
docker build -t articlems-backend .
```

### Run with Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: articledb
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: your_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      PGHOST: postgres
      PGPORT: 5432
      PGDATABASE: articledb
      PGUSER: postgres
      PGPASSWORD: your_password
      JWT_SECRET: your-jwt-secret
      SENDGRID_API_KEY: your-sendgrid-key
      SENDGRID_FROM_EMAIL: noreply@yourdomain.com
      FRONTEND_URL: http://localhost:3000
    depends_on:
      - postgres

volumes:
  postgres_data:
```

Run:
```bash
docker-compose up -d
```

---

## 🧪 Testing

### Run Tests

```bash
./mvnw test
```

### Test Coverage

```bash
./mvnw clean verify jacoco:report
```

### API Testing with cURL

**Register User:**
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"test@example.com","password":"Test@1234"}'
```

**Login:**
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test@1234"}'
```

**Create Article:**
```bash
curl -X POST http://localhost:8080/api/articles \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Test Article","content":"This is test content"}'
```

---

## 📚 Concepts Strengthened

This project helps you master the following concepts:

### 1. **Spring Boot & Spring Framework**
- Dependency Injection & IoC Container
- Spring MVC architecture
- Auto-configuration
- Application properties management

### 2. **RESTful API Design**
- HTTP methods (GET, POST, PUT, DELETE)
- Status codes usage
- Resource naming conventions
- Pagination and filtering

### 3. **Spring Security**
- Authentication vs Authorization
- JWT token-based authentication
- SecurityFilterChain configuration
- UserDetailsService implementation
- Password encoding

### 4. **Spring Data JPA**
- Entity relationships (OneToMany, ManyToOne)
- Custom query methods
- JPQL queries
- Transaction management
- Connection pooling

### 5. **Database Design**
- Normalization
- Indexing strategies
- Foreign key relationships
- Timestamp management

### 6. **Exception Handling**
- Global exception handler (@RestControllerAdvice)
- Custom exceptions
- Error response standardization
- HTTP status code mapping

### 7. **Validation**
- Bean Validation (Jakarta Validation)
- Custom validation annotations
- Method-level validation
- Error message customization

### 8. **Async Processing**
- @Async annotation
- ThreadPoolTaskExecutor
- Non-blocking operations
- Email sending optimization

### 9. **Retry Mechanism**
- @Retryable annotation
- Exponential backoff
- Error recovery strategies
- Resilience patterns

### 10. **Caching**
- Spring Cache abstraction
- Caffeine cache provider
- Cache eviction strategies
- Performance optimization

### 11. **Rate Limiting**
- Token bucket algorithm
- Bucket4j library
- Per-IP rate limiting
- DoS attack prevention

### 12. **Email Integration**
- SMTP configuration
- SendGrid API
- HTML email templates
- Thymeleaf template engine

### 13. **Docker & Containerization**
- Multi-stage Docker builds
- Docker Compose orchestration
- Environment variable management
- Container networking

### 14. **Design Patterns**
- Repository pattern
- Service layer pattern
- DTO pattern
- Builder pattern
- Strategy pattern

### 15. **Testing**
- Unit testing
- Integration testing
- Test-driven development (TDD)
- Mock objects

### 16. **Security Best Practices**
- Password hashing
- Token expiration
- Account lockout
- CORS configuration
- SQL injection prevention

---

## 🐛 Troubleshooting

### Common Issues

#### 1. Email Not Sending
```
Error: Failed to send verification email
```

**Solution:**
- Verify SendGrid API key is correct
- Check `app.email.enabled=true` in properties
- Verify sender email is authenticated in SendGrid
- Check SendGrid account status

---

#### 2. Database Connection Failed
```
Error: Connection refused to localhost:5432
```

**Solution:**
- Ensure PostgreSQL is running
- Verify database credentials
- Check database exists
- Verify port is not blocked

---

#### 3. JWT Token Invalid
```
Error: Invalid JWT signature
```

**Solution:**
- Verify JWT_SECRET is set correctly
- Ensure same secret across restarts
- Check token hasn't expired
- Verify Bearer token format

---

#### 4. Rate Limit Issues
```
Error: Too many requests
```

**Solution:**
- Wait for rate limit window to reset
- Increase rate limits in properties
- Use different IP for testing
- Check rate limit cache configuration

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License.

---

## 👥 Contact

**Developer:** Aryan Jaiswal
**Email:** aryanjai.works@gmail.com 
**Project Link:** [https://github.com/yourusername/ArticleMS-Backend](https://github.com/yourusername/ArticleMS-Backend)

---

## 🙏 Acknowledgments

- Spring Boot Documentation
- Baeldung Tutorials
- SendGrid Documentation
- PostgreSQL Documentation
- Stack Overflow Community

---

**Happy Coding! 🚀**


# 🔐 Spring Boot 3.0 Security with JWT Implementation

Bu proje, **Spring Boot 3.0** ve **JSON Web Tokens (JWT)** kullanarak modern, stateless authentication ve authorization sisteminin nasıl implement edileceğini gösterir.

---

## 📋 İçindekiler

1. [Özellikler](#-özellikler)
2. [Teknolojiler](#-teknolojiler)
3. [Kurulum](#-kurulum)
4. [Spring Security Felsefesi](#-spring-security-felsefesi)
5. [JWT Authentication Flow](#-jwt-authentication-flow)
6. [Proje Mimarisi](#-proje-mimarisi)
7. [Projeyi Nasıl Okumak Gerekir?](#-projeyi-nasıl-okumak-gerekir)
8. [API Endpoints](#-api-endpoints)
9. [Örnek Kullanım](#-örnek-kullanım)
10. [Güvenlik Notları](#-güvenlik-notları)
11. [TODO İyileştirmeler](#-todo-iyileştirmeler)

---

## ✨ Özellikler

- ✅ **User Registration & Login** - JWT authentication ile kullanıcı kaydı ve girişi
- ✅ **Password Encryption** - BCrypt ile şifre hashleme
- ✅ **Role-Based Authorization** - Spring Security ile rol bazlı yetkilendirme
- ✅ **Permission-Based Authorization** - Granular permission kontrolü
- ✅ **JWT Access Token** - Stateless authentication için JWT token
- ✅ **JWT Refresh Token** - Access token yenilemek için refresh token
- ✅ **Token Revocation** - Logout ile token iptal etme
- ✅ **Custom Access Denied Handling** - Özelleştirilmiş 403 Forbidden response
- ✅ **Swagger/OpenAPI Documentation** - API dokümantasyonu

---

## 🛠 Teknolojiler

| Teknoloji | Versiyon | Açıklama |
|-----------|----------|----------|
| **Java** | 17+ | Modern Java features (Records, Text Blocks, vb.) |
| **Spring Boot** | 3.0+ | Framework |
| **Spring Security** | 6.0+ | Authentication & Authorization |
| **Spring Data JPA** | 3.0+ | Database ORM |
| **PostgreSQL** | 14+ | Relational database |
| **JJWT** | 0.11.5 | JWT token generation & validation |
| **BCrypt** | - | Password hashing algorithm |
| **Lombok** | 1.18.26 | Boilerplate code reduction |
| **SpringDoc OpenAPI** | 2.0.2 | Swagger UI |
| **Maven** | 3+ | Build tool |

---

## 🚀 Kurulum

### **Gereksinimler**
- JDK 17+
- Maven 3+
- PostgreSQL 14+

### **Adımlar**

1. **Projeyi klonla:**
   ```bash
   git clone https://github.com/gokhandegerli/spring-boot-3-jwt-security.git
   cd spring-boot-3-jwt-security
   ```

2. **PostgreSQL database oluştur:**
   ```sql
   CREATE DATABASE jwt_security;
   ```

3. **application.yml dosyasını düzenle:**
   ```yaml
   spring:
     datasource:
       url: jdbc:postgresql://localhost:5432/jwt_security
       username: your_username
       password: your_password
   ```

4. **Projeyi build et:**
   ```bash
   mvn clean install
   ```

5. **Projeyi çalıştır:**
   ```bash
   mvn spring-boot:run
   ```

6. **Uygulamaya eriş:**
    - API: http://localhost:8080
    - Swagger UI: http://localhost:8080/swagger-ui.html

---

## 🧠 Spring Security Felsefesi

### **1. Authentication vs Authorization**

| Kavram | Açıklama | Örnek |
|--------|----------|-------|
| **Authentication** | "Sen kimsin?" sorusuna cevap | Login (email + password) |
| **Authorization** | "Ne yapma yetkin var?" sorusuna cevap | Admin paneline erişim |

### **2. Spring Security Filter Chain**

Spring Security, **Filter Chain** pattern'i kullanır. Her HTTP request, bir dizi filter'dan geçer:

```
HTTP Request
    ↓
1. SecurityContextPersistenceFilter (SecurityContext yükle)
    ↓
2. JwtAuthenticationFilter (JWT token validate et) ← BU PROJEDEKİ CUSTOM FILTER
    ↓
3. UsernamePasswordAuthenticationFilter (username/password authentication)
    ↓
4. ExceptionTranslationFilter (exception handling)
    ↓
5. FilterSecurityInterceptor (authorization - role/permission kontrolü)
    ↓
Controller Method
    ↓
HTTP Response
```

### **3. SecurityContext**

**SecurityContext**, Spring Security'nin **thread-local storage**'ıdır. Her thread için ayrı bir SecurityContext tutar.

```java
// SecurityContext'e Authentication set et
SecurityContextHolder.getContext().setAuthentication(authToken);

// SecurityContext'ten Authentication al
Authentication auth = SecurityContextHolder.getContext().getAuthentication();

// Current user'ı al
User user = (User) auth.getPrincipal();
```

### **4. Stateless Authentication**

**Stateful (Session-based):**
- Server'da session tutar (memory/database)
- Her request'te session ID gönderilir
- Scalability sorunu (load balancer, multiple server)

**Stateless (JWT-based):**
- Server'da session tutmaz
- Her request'te JWT token gönderilir
- Token içinde user bilgisi var (self-contained)
- Scalability kolay (horizontal scaling)

---

## 🔄 JWT Authentication Flow

### **1. Registration Flow**

```
Client                          Server
  |                               |
  |  POST /api/v1/auth/register   |
  |  { email, password, ... }     |
  |------------------------------>|
  |                               |
  |                               | 1. Password'ü BCrypt ile hashle
  |                               | 2. User'ı DB'ye kaydet
  |                               | 3. JWT access token oluştur
  |                               | 4. JWT refresh token oluştur
  |                               | 5. Token'ları DB'ye kaydet
  |                               |
  |  { access_token, refresh_token }
  |<------------------------------|
  |                               |
```

### **2. Login Flow**

```
Client                          Server
  |                               |
  |  POST /api/v1/auth/authenticate |
  |  { email, password }          |
  |------------------------------>|
  |                               |
  |                               | 1. User'ı DB'den bul (email)
  |                               | 2. Password'ü BCrypt ile kontrol et
  |                               | 3. AuthenticationManager.authenticate()
  |                               | 4. JWT access token oluştur
  |                               | 5. JWT refresh token oluştur
  |                               | 6. Eski token'ları revoke et
  |                               | 7. Yeni token'ları DB'ye kaydet
  |                               |
  |  { access_token, refresh_token }
  |<------------------------------|
  |                               |
```

### **3. Authenticated Request Flow**

```
Client                          Server
  |                               |
  |  GET /api/v1/books            |
  |  Authorization: Bearer <JWT>  |
  |------------------------------>|
  |                               |
  |                               | JwtAuthenticationFilter:
  |                               | 1. Authorization header'dan JWT al
  |                               | 2. JWT'den username (email) çıkar
  |                               | 3. User'ı DB'den yükle
  |                               | 4. Token'ı validate et:
  |                               |    - Signature valid mi?
  |                               |    - Expired değil mi?
  |                               |    - Revoked değil mi?
  |                               | 5. SecurityContext'e Authentication set et
  |                               |
  |                               | FilterSecurityInterceptor:
  |                               | 6. Role/Permission kontrolü yap
  |                               | 7. Controller method'u çağır
  |                               |
  |  [ { book1 }, { book2 }, ... ] |
  |<------------------------------|
  |                               |
```

### **4. Refresh Token Flow**

```
Client                          Server
  |                               |
  |  POST /api/v1/auth/refresh-token |
  |  Authorization: Bearer <REFRESH_TOKEN> |
  |------------------------------>|
  |                               |
  |                               | 1. Refresh token'ı validate et
  |                               | 2. User'ı DB'den yükle
  |                               | 3. Yeni access token oluştur
  |                               | 4. Yeni refresh token oluştur
  |                               | 5. Eski token'ları revoke et
  |                               | 6. Yeni token'ları DB'ye kaydet
  |                               |
  |  { access_token, refresh_token }
  |<------------------------------|
  |                               |
```

### **5. Logout Flow**

```
Client                          Server
  |                               |
  |  POST /api/v1/auth/logout     |
  |  Authorization: Bearer <JWT>  |
  |------------------------------>|
  |                               |
  |                               | LogoutService:
  |                               | 1. JWT token'ı DB'de bul
  |                               | 2. Token'ı revoke et (expired=true, revoked=true)
  |                               | 3. SecurityContext'i temizle
  |                               |
  |  200 OK                       |
  |<------------------------------|
  |                               |
```

---

## 🏗 Proje Mimarisi

### **Layered Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                     PRESENTATION LAYER                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Auth         │  │ User         │  │ Book         │      │
│  │ Controller   │  │ Controller   │  │ Controller   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                       SERVICE LAYER                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Auth         │  │ User         │  │ Book         │      │
│  │ Service      │  │ Service      │  │ Service      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐                         │
│  │ JWT          │  │ Logout       │                         │
│  │ Service      │  │ Service      │                         │
│  └──────────────┘  └──────────────┘                         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                     REPOSITORY LAYER                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ User         │  │ Token        │  │ Book         │      │
│  │ Repository   │  │ Repository   │  │ Repository   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                       DOMAIN LAYER                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ User         │  │ Token        │  │ Book         │      │
│  │ Entity       │  │ Entity       │  │ Entity       │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐                         │
│  │ Role         │  │ Permission   │                         │
│  │ Enum         │  │ Enum         │                         │
│  └──────────────┘  └──────────────┘                         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                         DATABASE                             │
│                       PostgreSQL                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    SECURITY/CONFIG LAYER                     │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ SecurityConfiguration                                 │   │
│  │ - Filter chain configuration                          │   │
│  │ - URL authorization rules                             │   │
│  │ - CORS configuration                                  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ JwtAuthenticationFilter                               │   │
│  │ - JWT token validation                                │   │
│  │ - SecurityContext population                          │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ ApplicationConfig                                     │   │
│  │ - UserDetailsService bean                             │   │
│  │ - AuthenticationProvider bean                         │   │
│  │ - PasswordEncoder bean                                │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### **Package Structure**

```
com.degerli.security
├── config/                          # Security & Application Configuration
│   ├── ApplicationConfig.java       # Bean definitions (UserDetailsService, AuthenticationProvider, vb.)
│   ├── JwtAuthenticationFilter.java # JWT token validation filter
│   ├── LogoutService.java           # Logout handler
│   ├── OpenApiConfig.java           # Swagger/OpenAPI configuration
│   ├── SecurityConfiguration.java   # Spring Security configuration
│   └── ApplicationAuditAware.java   # JPA Auditing configuration
│
├── user/                            # User Domain
│   ├── User.java                    # User entity (UserDetails implementation)
│   ├── Role.java                    # Role enum (ADMIN, MANAGER, USER)
│   ├── Permission.java              # Permission enum (granular permissions)
│   ├── UserRepository.java          # User data access
│   ├── UserService.java             # User business logic
│   └── UserController.java          # User REST endpoints
│
├── token/                           # Token Domain
│   ├── Token.java                   # Token entity (JWT token storage)
│   ├── TokenType.java               # Token type enum (BEARER)
│   └── TokenRepository.java         # Token data access
│
├── auth/                            # Authentication Domain
│   ├── AuthenticationService.java   # Authentication business logic
│   ├── AuthenticationController.java # Auth REST endpoints (register, login, refresh, logout)
│   ├── AuthenticationRequest.java   # Login request DTO
│   ├── AuthenticationResponse.java  # Login response DTO (access_token, refresh_token)
│   └── RegisterRequest.java         # Registration request DTO
│
├── book/                            # Book Domain (Example Resource)
│   ├── Book.java                    # Book entity
│   ├── BookRepository.java          # Book data access
│   ├── BookService.java             # Book business logic
│   ├── BookController.java          # Book REST endpoints
│   └── BookRequest.java             # Book request DTO
│
├── demo/                            # Demo Controllers (Testing Authorization)
│   ├── DemoController.java          # Public demo endpoint
│   ├── AdminController.java         # Admin-only endpoints
│   └── ManagementController.java    # Manager-only endpoints
│
└── SecurityApplication.java         # Spring Boot main class
```

---

## 📖 Projeyi Nasıl Okumak Gerekir?

### **🎯 Öğrenme Yol Haritası**

Projeyi anlamak için **aşağıdaki sırayı** takip etmenizi öneririm:

---

### **ADIM 1: Domain Layer'ı Anla (Veri Modeli)**

**Okuma Sırası:**
1. `User.java` - Kullanıcı entity'si (UserDetails implementation)
2. `Role.java` - Rol enum'u (ADMIN, MANAGER, USER)
3. `Permission.java` - Permission enum'u (granular permissions)
4. `Token.java` - JWT token entity'si
5. `TokenType.java` - Token type enum'u

**Dikkat Edilmesi Gerekenler:**
- ✅ `User` class'ı `UserDetails` interface'ini implement ediyor (Spring Security requirement)
- ✅ `getAuthorities()` method'u role ve permission'ları `GrantedAuthority` listesine dönüştürüyor
- ✅ `Role` enum'u içinde `permissions` listesi var (role → permissions mapping)
- ✅ `Token` entity'si `user` ile `@ManyToOne` ilişkisi var (bir user'ın birden fazla token'ı olabilir)

**Sorular:**
- ❓ `UserDetails` interface'i neden gerekli?
- ❓ `GrantedAuthority` nedir?
- ❓ Role ve Permission arasındaki fark nedir?
- ❓ Token neden DB'de tutuluyor?

---

### **ADIM 2: Repository Layer'ı Anla (Data Access)**

**Okuma Sırası:**
1. `UserRepository.java` - User data access
2. `TokenRepository.java` - Token data access
3. `BookRepository.java` - Book data access

**Dikkat Edilmesi Gerekenler:**
- ✅ `UserRepository.findByEmail()` - Login için kullanılıyor
- ✅ `TokenRepository.findAllValidTokenByUser()` - User'ın valid token'larını buluyor
- ✅ `TokenRepository.findByToken()` - JWT token'ı validate ederken kullanılıyor
- ⚠️ **BUG:** `findAllValidTokenByUser()` query'sinde `OR` yerine `AND` kullanılmalı!

**Sorular:**
- ❓ `Optional<User>` neden kullanılıyor?
- ❓ `@Query` annotation'ı ne işe yarıyor?
- ❓ Token revocation nasıl çalışıyor?

---

### **ADIM 3: Config Layer'ı Anla (Spring Security Configuration)**

**Okuma Sırası:**
1. `ApplicationConfig.java` - Bean definitions
2. `SecurityConfiguration.java` - Security configuration
3. `JwtAuthenticationFilter.java` - JWT filter
4. `LogoutService.java` - Logout handler

**Dikkat Edilmesi Gerekenler:**

#### **ApplicationConfig.java:**
- ✅ `userDetailsService()` - User'ı email ile yükleyen bean
- ✅ `authenticationProvider()` - Authentication provider bean
- ✅ `passwordEncoder()` - BCrypt password encoder bean
- ✅ `authenticationManager()` - Authentication manager bean

#### **SecurityConfiguration.java:**
- ✅ `securityFilterChain()` - Filter chain configuration
- ✅ Whitelisted URLs: `/api/v1/auth/**` (permitAll)
- ✅ Role-based authorization: `/api/v1/admin/**` (ADMIN only)
- ✅ Permission-based authorization: `/api/v1/management/**` (specific permissions)
- ✅ Stateless session management: `SessionCreationPolicy.STATELESS`
- ✅ JWT filter: `addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)`

#### **JwtAuthenticationFilter.java:**
- ✅ `OncePerRequestFilter` extend ediyor (her request'te bir kez çalışır)
- ✅ Authorization header'dan JWT token'ı alıyor
- ✅ Token'ı validate ediyor (signature, expiration, revocation)
- ✅ User'ı yüklüyor (`UserDetailsService`)
- ✅ SecurityContext'e Authentication set ediyor

#### **LogoutService.java:**
- ✅ `LogoutHandler` interface'ini implement ediyor
- ✅ Token'ı DB'de bulup revoke ediyor
- ✅ SecurityContext'i temizliyor

**Sorular:**
- ❓ `UserDetailsService` neden bean olarak tanımlanıyor?
- ❓ `AuthenticationProvider` ne işe yarıyor?
- ❓ Filter chain sırası neden önemli?
- ❓ `SessionCreationPolicy.STATELESS` ne demek?
- ❓ SecurityContext nedir, nasıl çalışır?

---

### **ADIM 4: Service Layer'ı Anla (Business Logic)**

**Okuma Sırası:**
1. `JwtService.java` - JWT token operations
2. `AuthenticationService.java` - Authentication logic
3. `UserService.java` - User operations
4. `BookService.java` - Book operations

**Dikkat Edilmesi Gerekenler:**

#### **JwtService.java:**
- ✅ `extractUsername()` - JWT'den username (email) çıkarıyor
- ✅ `generateToken()` - Access token oluşturuyor (24 saat)
- ✅ `generateRefreshToken()` - Refresh token oluşturuyor (7 gün)
- ✅ `isTokenValid()` - Token'ı validate ediyor
- ⚠️ **SECURITY WARNING:** Secret key hardcoded (externalize edilmeli!)
- ⚠️ **DEPRECATED:** `SignatureAlgorithm.HS256` yerine `HS512` kullanılmalı!

#### **AuthenticationService.java:**
- ✅ `register()` - User kaydı + token generation
- ✅ `authenticate()` - Login + token generation
- ✅ `refreshToken()` - Refresh token ile yeni token alma
- ✅ `saveUserToken()` - Token'ı DB'ye kaydetme
- ✅ `revokeAllUserTokens()` - User'ın tüm token'larını revoke etme

#### **UserService.java:**
- ✅ `changePassword()` - Password değiştirme
- ✅ Eski password kontrolü yapıyor
- ✅ Yeni password'ü BCrypt ile hashliyor

**Sorular:**
- ❓ JWT token nasıl oluşturuluyor?
- ❓ Access token ve refresh token arasındaki fark nedir?
- ❓ Token revocation neden gerekli?
- ❓ BCrypt neden kullanılıyor?

---

### **ADIM 5: Controller Layer'ı Anla (REST API)**

**Okuma Sırası:**
1. `AuthenticationController.java` - Auth endpoints
2. `UserController.java` - User endpoints
3. `BookController.java` - Book endpoints
4. `DemoController.java`, `AdminController.java`, `ManagementController.java` - Demo endpoints

**Dikkat Edilmesi Gerekenler:**

#### **AuthenticationController.java:**
- ✅ `POST /api/v1/auth/register` - User registration
- ✅ `POST /api/v1/auth/authenticate` - Login
- ✅ `POST /api/v1/auth/refresh-token` - Refresh token

#### **UserController.java:**
- ✅ `PATCH /api/v1/users` - Change password
- ✅ `@PreAuthorize("hasRole('USER')")` - Role-based authorization

#### **BookController.java:**
- ✅ `POST /api/v1/books` - Create book
- ✅ `GET /api/v1/books` - Get all books
- ✅ `@PreAuthorize("hasRole('ADMIN')")` - Admin-only endpoint

#### **Demo Controllers:**
- ✅ `AdminController` - `@PreAuthorize("hasRole('ADMIN')")`
- ✅ `ManagementController` - `@PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")`

**Sorular:**
- ❓ `@PreAuthorize` annotation'ı nasıl çalışıyor?
- ❓ `@AuthenticationPrincipal` ne işe yarıyor?
- ❓ Role-based ve permission-based authorization arasındaki fark nedir?

---

### **ADIM 6: Authentication Flow'u Test Et**

**Test Senaryosu:**
1. ✅ User registration yap
2. ✅ Login yap (access token + refresh token al)
3. ✅ Protected endpoint'e request at (JWT token ile)
4. ✅ Refresh token ile yeni access token al
5. ✅ Logout yap (token revoke et)
6. ✅ Revoked token ile request at (403 Forbidden almalısın)

---

## 🔌 API Endpoints

### **Authentication Endpoints**

| Method | Endpoint | Description | Auth Required | Role Required |
|--------|----------|-------------|---------------|---------------|
| `POST` | `/api/v1/auth/register` | User registration | ❌ No | - |
| `POST` | `/api/v1/auth/authenticate` | User login | ❌ No | - |
| `POST` | `/api/v1/auth/refresh-token` | Refresh access token | ✅ Yes (Refresh Token) | - |
| `POST` | `/api/v1/auth/logout` | Logout (revoke token) | ✅ Yes | - |

### **User Endpoints**

| Method | Endpoint | Description | Auth Required | Role Required |
|--------|----------|-------------|---------------|---------------|
| `PATCH` | `/api/v1/users` | Change password | ✅ Yes | `USER` |

### **Book Endpoints**

| Method | Endpoint | Description | Auth Required | Role Required |
|--------|----------|-------------|---------------|---------------|
| `POST` | `/api/v1/books` | Create book | ✅ Yes | `ADMIN` |
| `GET` | `/api/v1/books` | Get all books | ✅ Yes | `USER` |
| `GET` | `/api/v1/books/{id}` | Get book by ID | ✅ Yes | `USER` |

### **Demo Endpoints (Authorization Testing)**

| Method | Endpoint | Description | Auth Required | Role Required |
|--------|----------|-------------|---------------|---------------|
| `GET` | `/api/v1/demo-controller` | Public demo endpoint | ✅ Yes | `USER` |
| `GET` | `/api/v1/admin` | Admin-only endpoint | ✅ Yes | `ADMIN` |
| `POST` | `/api/v1/admin` | Admin-only endpoint | ✅ Yes | `ADMIN` |
| `PUT` | `/api/v1/admin` | Admin-only endpoint | ✅ Yes | `ADMIN` |
| `DELETE` | `/api/v1/admin` | Admin-only endpoint | ✅ Yes | `ADMIN` |
| `GET` | `/api/v1/management` | Manager-only endpoint | ✅ Yes | `ADMIN` or `MANAGER` |
| `POST` | `/api/v1/management` | Manager-only endpoint | ✅ Yes | `ADMIN` or `MANAGER` |
| `PUT` | `/api/v1/management` | Manager-only endpoint | ✅ Yes | `ADMIN` or `MANAGER` |
| `DELETE` | `/api/v1/management` | Manager-only endpoint | ✅ Yes | `ADMIN` or `MANAGER` |

---

## 📝 Örnek Kullanım

### **1. User Registration**

**Request:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "firstname": "John",
    "lastname": "Doe",
    "email": "john.doe@example.com",
    "password": "password123",
    "role": "USER"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### **2. User Login**

**Request:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/authenticate \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "password123"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### **3. Access Protected Endpoint**

**Request:**
```bash
curl -X GET http://localhost:8080/api/v1/books \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Response:**
```json
[
  {
    "id": 1,
    "author": "J.K. Rowling",
    "isbn": "978-0439708180"
  },
  {
    "id": 2,
    "author": "George Orwell",
    "isbn": "978-0451524935"
  }
]
```

---

### **4. Refresh Access Token**

**Request:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh-token \
  -H "Authorization: Bearer <REFRESH_TOKEN>"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### **5. Change Password**

**Request:**
```bash
curl -X PATCH http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "currentPassword": "password123",
    "newPassword": "newPassword456",
    "confirmationPassword": "newPassword456"
  }'
```

**Response:**
```
200 OK
```

---

### **6. Logout**

**Request:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

**Response:**
```
200 OK
```

---

### **7. Access Admin-Only Endpoint**

**Request (with USER role):**
```bash
curl -X GET http://localhost:8080/api/v1/admin \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

**Response:**
```
403 Forbidden
```

**Request (with ADMIN role):**
```bash
curl -X GET http://localhost:8080/api/v1/admin \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

**Response:**
```json
{
  "message": "GET:: admin controller"
}
```

---

## 🔒 Güvenlik Notları

### **⚠️ PRODUCTION İÇİN GEREKLİ DEĞİŞİKLİKLER:**

1. **❌ Secret Key Hardcoded:**
   ```java
   // ❌ YANLIŞ (JwtService.java)
   private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
   
   // ✅ DOĞRU
   @Value("${application.security.jwt.secret-key}")
   private String secretKey;
   ```

   **Çözüm:** Environment variable veya application.yml'den oku.

2. **❌ Deprecated Algorithm:**
   ```java
   // ❌ YANLIŞ
   .signWith(getSignInKey(), SignatureAlgorithm.HS256)
   
   // ✅ DOĞRU
   .signWith(getSignInKey(), SignatureAlgorithm.HS512)
   ```

3. **❌ Token Repository Query Bug:**
   ```java
   // ❌ YANLIŞ (TokenRepository.java)
   @Query(value = """
       select t from Token t inner join User u
       on t.user.id = u.id
       where u.id = :id and (t.expired = false or t.revoked = false)
       """)
   
   // ✅ DOĞRU
   @Query(value = """
       select t from Token t inner join User u
       on t.user.id = u.id
       where u.id = :id and (t.expired = false and t.revoked = false)
       """)
   ```

4. **❌ Exception Handling Eksik:**
    - JWT parse exception handling yok
    - Custom error messages yok
    - Logging yok

5. **❌ Rate Limiting Yok:**
    - Brute force attack'lere karşı koruma yok
    - Login attempt limit yok

6. **❌ Email Verification Yok:**
    - User registration sonrası email verification yok
    - Email duplicate kontrolü yok

7. **❌ Password Strength Validation Yok:**
    - Minimum password length kontrolü yok
    - Password complexity kontrolü yok

8. **❌ Audit Logging Yok:**
    - Failed login attempts loglanmıyor
    - Security events loglanmıyor

9. **❌ CORS Configuration Eksik:**
    - Frontend'den erişim için CORS configuration gerekli

10. **❌ Redis Cache Yok:**
    - Her request'te DB query yapılıyor (performance sorunu)
    - Token validation cache'lenmiyor

---

## 🚀 TODO İyileştirmeler

### **🔴 Kritik (Production için gerekli):**
- [ ] Secret key'i externalize et (environment variable)
- [ ] `SignatureAlgorithm.HS256` → `HS512` değiştir
- [ ] `TokenRepository.findAllValidTokenByUser()` query'sini düzelt (`OR` → `AND`)
- [ ] Exception handling ekle (custom error messages)
- [ ] CORS configuration ekle
- [ ] Rate limiting ekle (brute force attack'lere karşı)

### **🟡 Önemli (Güvenlik için önerilen):**
- [ ] Email verification ekle (user registration sonrası)
- [ ] Password strength validation ekle
- [ ] Audit logging ekle (failed login attempts, security events)
- [ ] Password reset functionality ekle
- [ ] Account locking ekle (failed login attempts sonrası)
- [ ] Multi-factor authentication (MFA) ekle

### **🟢 İyileştirme (Performance & UX):**
- [ ] Redis cache ekle (user ve token için)
- [ ] Token blacklist ekle (revoked token'ları cache'le)
- [ ] Refresh token rotation ekle (security için)
- [ ] Email notification ekle (password change, login, vb.)
- [ ] User profile endpoints ekle (GET, PUT, DELETE)
- [ ] Pagination ekle (book list için)
- [ ] Search & filter ekle (book list için)

### **🔵 Dokümantasyon:**
- [x] Comprehensive README.md
- [ ] Postman collection ekle
- [ ] Architecture diagram ekle
- [ ] Sequence diagram ekle (authentication flow)
- [ ] API documentation (Swagger) customize et

---

## 📚 Kaynaklar

### **Spring Security:**
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/index.html)
- [Spring Security Architecture](https://spring.io/guides/topicals/spring-security-architecture)

### **JWT:**
- [JWT.io](https://jwt.io/)
- [RFC 7519 - JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)

### **BCrypt:**
- [BCrypt Wikipedia](https://en.wikipedia.org/wiki/Bcrypt)

### **Best Practices:**
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---


Bu proje, Spring Security ve JWT authentication'ı öğrenmek isteyenler için bir başlangıç noktasıdır. Production'da kullanmadan önce yukarıdaki güvenlik notlarını ve TODO listesini mutlaka inceleyin!

**Happy Coding! 🚀**
```

---

Bu README:

1. ✅ **Spring Security felsefesini** detaylı açıklıyor
2. ✅ **JWT authentication flow**'unu adım adım gösteriyor
3. ✅ **Proje mimarisini** görsel olarak sunuyor
4. ✅ **Öğrenme yol haritası** veriyor (hangi sırayla okunmalı)
5. ✅ **Her layer için dikkat edilmesi gerekenleri** belirtiyor
6. ✅ **API endpoint'leri** ve **örnek kullanımları** gösteriyor
7. ✅ **Güvenlik notlarını** ve **TODO listesini** içeriyor


package com.degerli.security.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;

/**
 * OpenApiConfig - Swagger/OpenAPI Configuration
 *
 * <p><b>NE:</b> Swagger/OpenAPI documentation configuration'ı.
 * API documentation için metadata, security scheme, server bilgileri tanımlar.</p>
 *
 * <p><b>NEDEN:</b>
 * - API documentation sağlamak (Swagger UI)
 * - API endpoint'lerini test etmek için UI sağlamak
 * - JWT authentication'ı Swagger UI'da kullanabilmek
 * - API metadata'sını (title, description, version, contact, license) tanımlamak
 * - Development ve production server bilgilerini tanımlamak
 * </p>
 *
 * <p><b>NASIL:</b>
 *
 * <b>1. @OpenAPIDefinition:</b>
 * - API metadata'sını tanımlar
 * - Info: title, description, version, contact, license
 * - Servers: development ve production server URL'leri
 * - Security: Global security requirement (JWT Bearer token)
 *
 * <b>2. @SecurityScheme:</b>
 * - JWT Bearer token authentication scheme tanımlar
 * - Type: HTTP Bearer
 * - Scheme: bearer
 * - Bearer Format: JWT
 * - In: Header (Authorization header)
 *
 * <b>3. SWAGGER UI ACCESS:</b>
 * - URL: http://localhost:8080/swagger-ui/index.html
 * - SecurityConfiguration'da whitelisted (authentication gerektirmez)
 * </p>
 *
 * <p><b>SWAGGER UI KULLANIMI:</b>
 *
 * <b>1. Swagger UI'a git:</b>
 * http://localhost:8080/swagger-ui/index.html
 *
 * <b>2. Register endpoint'i ile kullanıcı oluştur:</b>
 * POST /api/v1/auth/register
 * {
 * "firstname": "Gokhan",
 * "lastname": "Degerli",
 * "email": "gokhan@mail.com",
 * "password": "password",
 * "role": "USER"
 * }
 *
 * <b>3. Login endpoint'i ile token al:</b>
 * POST /api/v1/auth/authenticate
 * {
 * "email": "gokhan@mail.com",
 * "password": "password"
 * }
 * Response: { "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }
 *
 * <b>4. Swagger UI'da "Authorize" butonuna tıkla:</b>
 * - "Authorize" butonuna tıkla (sağ üstte)
 * - "Value" field'ına token'ı yapıştır (Bearer prefix'i otomatik eklenir)
 * - "Authorize" butonuna tıkla
 * - "Close" butonuna tıkla
 *
 * <b>5. Artık tüm endpoint'leri test edebilirsin:</b>
 * - GET /api/v1/books
 * - POST /api/v1/books
 * - GET /api/v1/demo-controller
 * - vb.
 * </p>
 *
 * <p><b>SECURITY SCHEME DETAYLARI:</b>
 *
 * <b>name = "bearerAuth":</b>
 * - Security scheme'in adı
 * - @SecurityRequirement(name = "bearerAuth") ile referans edilir
 *
 * <b>type = SecuritySchemeType.HTTP:</b>
 * - HTTP authentication scheme
 * - Alternatifler: API_KEY, OAUTH2, OPENIDCONNECT
 *
 * <b>scheme = "bearer":</b>
 * - Bearer token authentication
 * - Authorization header: "Bearer <token>"
 *
 * <b>bearerFormat = "JWT":</b>
 * - Token formatı JWT
 * - Swagger UI'da gösterilir (bilgilendirme amaçlı)
 *
 * <b>in = SecuritySchemeIn.HEADER:</b>
 * - Token, HTTP header'da gönderilir
 * - Header name: "Authorization"
 * - Header value: "Bearer <token>"
 * </p>
 *
 * <p><b>OPENAPI DEFINITION DETAYLARI:</b>
 *
 * <b>info.title:</b>
 * - API'nin başlığı
 * - Swagger UI'da gösterilir
 *
 * <b>info.description:</b>
 * - API'nin açıklaması
 * - Swagger UI'da gösterilir
 *
 * <b>info.version:</b>
 * - API versiyonu
 * - Semantic versioning kullanılır (1.0, 2.0, vb.)
 *
 * <b>info.contact:</b>
 * - API sahibinin iletişim bilgileri
 * - name, email, url
 *
 * <b>info.license:</b>
 * - API lisansı
 * - name, url
 *
 * <b>servers:</b>
 * - API server URL'leri
 * - Development, staging, production server'ları tanımlanabilir
 * - Swagger UI'da server seçimi yapılabilir
 *
 * <b>security:</b>
 * - Global security requirement
 * - Tüm endpoint'ler için geçerli
 * - Endpoint bazında override edilebilir (@SecurityRequirement annotation ile)
 * </p>
 *
 * <p><b>TODO İYİLEŞTİRMELER:</b>
 * - Production server URL'i ekle
 * - API versioning ekle (v1, v2, vb.)
 * - Custom Swagger UI theme ekle
 * - API examples ekle (request/response examples)
 * - Error response documentation ekle
 * - Rate limiting documentation ekle
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see SecurityConfiguration Swagger endpoint'lerini whitelisted yapar
 */
@OpenAPIDefinition(
    // API metadata
    info = @Info(
        // API başlığı
        title = "OpenApi specification - Gokhan",

        // API açıklaması
        description = "OpenApi documentation for Spring Security",

        // API versiyonu
        version = "1.0",

        // İletişim bilgileri
        contact = @Contact(name = "Gokhan",
            email = "contact@gokhan.com",
            url = "https://gokhan.com"),

        // Lisans bilgileri
        license = @License(name = "Licence name",
            url = "https://some-url.com")),

    // Server bilgileri
    servers = {@Server(description = "Local ENV",
        url = "http://localhost:8080"), @Server(description = "PROD ENV",
        url = "https://gokhan.com")},

    // Global security requirement (tüm endpoint'ler için JWT token gerekli)
    security = {@SecurityRequirement(name = "bearerAuth"
        // SecurityScheme name ile eşleşmeli
    )})
@SecurityScheme(
    // Security scheme adı (SecurityRequirement'ta kullanılır)
    name = "bearerAuth",

    // Security scheme açıklaması
    description = "JWT auth description",

    // Security scheme type (HTTP Bearer)
    type = SecuritySchemeType.HTTP,

    // Bearer token scheme
    scheme = "bearer",

    // Token formatı (JWT)
    bearerFormat = "JWT",

    // Token nerede gönderilir (HTTP Header)
    in = SecuritySchemeIn.HEADER)
public class OpenApiConfig {
  // Bu class sadece annotation'lar için kullanılır
  // Method veya field tanımlamaya gerek yok
}
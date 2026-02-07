package com.degerli.security.token;

/**
 * TokenType Enum - Token Tipi Tanımları
 *
 * <p><b>NE:</b> JWT token tiplerini tanımlayan enum.</p>
 *
 * <p><b>MEVCUT DURUM:</b> Sadece BEARER tipi kullanılıyor.</p>
 *
 * <p><b>BEARER TOKEN:</b>
 * - HTTP Authorization header'ında kullanılır
 * - Format: "Authorization: Bearer {token}"
 * - OAuth 2.0 standardı
 * - En yaygın JWT kullanım şekli
 * </p>
 *
 * <p><b>GELECEK GENİŞLEME:</b>
 * Farklı token tipleri eklenebilir:
 * - API_KEY: API key authentication için
 * - OAUTH2: OAuth2 token'ları için
 * - BASIC: Basic authentication için
 * </p>
 *
 * @author Gokhan Degerli
 * @version 1.0
 * @see Token Token entity'sinde kullanılır
 */
public enum TokenType {
  /**
   * Bearer Token Tipi
   *
   * <p>HTTP Authorization header'ında "Bearer {token}" formatında kullanılır.</p>
   *
   * <p><b>ÖRNEK:</b>
   * <pre>
   * Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   * </pre>
   * </p>
   */
  BEARER
}
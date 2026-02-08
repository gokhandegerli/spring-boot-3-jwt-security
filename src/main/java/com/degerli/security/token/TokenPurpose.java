package com.degerli.security.token;

/**
 * Token'ın amacını belirtir
 *
 * <p><b>ACCESS:</b> API endpoint'lerine erişim için kullanılır (kısa ömürlü)</p>
 * <p><b>REFRESH:</b> Yeni access token almak için kullanılır (uzun ömürlü)</p>
 *
 * <h3>Kullanım:</h3>
 * <pre>
 * // Access token
 * Token accessToken = Token.builder()
 *     .tokenType(TokenType.BEARER)
 *     .tokenPurpose(TokenPurpose.ACCESS)
 *     .build();
 *
 * // Refresh token
 * Token refreshToken = Token.builder()
 *     .tokenType(TokenType.BEARER)
 *     .tokenPurpose(TokenPurpose.REFRESH)
 *     .build();
 * </pre>
 *
 * @author Gökhan Değerli
 * @since 1.0
 */
public enum TokenPurpose {

  /**
   * Access token - API endpoint'lerine erişim için kullanılır
   *
   * <p><b>Özellikler:</b></p>
   * <ul>
   *   <li>Kısa ömürlü (örn: 15 dakika)</li>
   *   <li>Her API isteğinde gönderilir</li>
   *   <li>Expire olduğunda refresh token ile yenilenir</li>
   * </ul>
   */
  ACCESS,

  /**
   * Refresh token - Yeni access token almak için kullanılır
   *
   * <p><b>Özellikler:</b></p>
   * <ul>
   *   <li>Uzun ömürlü (örn: 7 gün)</li>
   *   <li>Sadece /refresh-token endpoint'ine gönderilir</li>
   *   <li>Expire olduğunda kullanıcı tekrar login olmalı</li>
   * </ul>
   */
  REFRESH
}
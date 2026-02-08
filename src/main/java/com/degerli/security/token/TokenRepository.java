package com.degerli.security.token;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface TokenRepository extends JpaRepository<Token, Integer> {

  /**
   * Kullanıcının tüm geçerli token'larını bulur (ACCESS ve REFRESH)
   */
  @Query("""
      select t from Token t
      where t.user.id = :id and t.expired = false and t.revoked = false
      """)
  List<Token> findAllValidTokenByUser(Integer id);


  /**
   * Kullanıcının belirli amaçtaki tüm geçerli token'larını bulur
   *
   * @param userId       Kullanıcı ID
   * @param tokenPurpose Token amacı (ACCESS veya REFRESH)
   * @return Geçerli token'lar
   */
  @Query("""
      select t from Token t inner join User u
      on t.user.id = u.id where u.id = :userId and t.tokenPurpose = :tokenPurpose and (t.expired = false and t.revoked = false)
      """)
  List<Token> findAllValidTokenByUserAndPurpose(Integer userId, TokenPurpose tokenPurpose);

  /**
   * Token string'i ile token bulur
   */
  Optional<Token> findByToken(String token);

  /**
   * Token string'i ve amacı ile token bulur
   *
   * @param token        Token string
   * @param tokenPurpose Token amacı (ACCESS veya REFRESH)
   * @return Token entity
   */
  Optional<Token> findByTokenAndTokenPurpose(String token, TokenPurpose tokenPurpose);
}
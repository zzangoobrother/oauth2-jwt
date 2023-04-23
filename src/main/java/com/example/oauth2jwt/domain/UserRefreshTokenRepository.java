package com.example.oauth2jwt.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRefreshTokenRepository extends JpaRepository<UserRefreshToken, Long> {
    Optional<UserRefreshToken> findByUserId(String userId);
    Optional<UserRefreshToken> findByUserIdAndRefreshToken(String userId, String refreshToken);
}

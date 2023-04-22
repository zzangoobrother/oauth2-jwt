package com.example.oauth2jwt.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRefreshTokenRepository extends JpaRepository<UserRefreshToken, Long> {
    Optional<UserRefreshToken> findByUserId(Long userId);
    Optional<UserRefreshToken> findByUserIdAndRefreshToken(Long userId, String refreshToken);
}

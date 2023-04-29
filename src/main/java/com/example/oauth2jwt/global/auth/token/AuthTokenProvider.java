package com.example.oauth2jwt.global.auth.token;

import com.example.oauth2jwt.global.auth.exception.TokenValidFailedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;

import java.security.Key;
import java.util.Collections;
import java.util.Date;

@Slf4j
public class AuthTokenProvider {
    private final Key key;

    public AuthTokenProvider(String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public AuthToken createAuthToken(String id, Date expiry) {
        return new AuthToken(id, expiry, key);
    }

    public AuthToken convertAuthToken(String token) {
        return new AuthToken(token, key);
    }

    public Authentication getAuthentication(AuthToken authToken) {
        if (authToken.validate()) {
            Claims claims = authToken.getTokenClaims();

            System.out.println("claims subject : " + claims.getSubject());
            User principal = new User(claims.getSubject(), "", Collections.emptyList());

            return new UsernamePasswordAuthenticationToken(principal, authToken, null);
        }

        throw new TokenValidFailedException();
    }
}

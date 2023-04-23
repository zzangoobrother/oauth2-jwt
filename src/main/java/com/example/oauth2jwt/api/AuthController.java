package com.example.oauth2jwt.api;

import com.example.oauth2jwt.domain.UserRefreshToken;
import com.example.oauth2jwt.domain.UserRefreshTokenRepository;
import com.example.oauth2jwt.dto.ApiResponse;
import com.example.oauth2jwt.dto.AuthRequest;
import com.example.oauth2jwt.global.auth.properties.AppProperties;
import com.example.oauth2jwt.global.auth.token.AuthToken;
import com.example.oauth2jwt.global.auth.token.AuthTokenProvider;
import com.example.oauth2jwt.global.utils.CookieUtil;
import com.example.oauth2jwt.global.utils.HeaderUtil;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;

@RestController
public class AuthController {
    private final static long THREE_DAYS_MSEC = 259200000;
    private final static String REFRESH_TOKEN = "refresh_token";

    private final AppProperties appProperties;
    private final AuthTokenProvider authTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final UserRefreshTokenRepository userRefreshTokenRepository;

    public AuthController(AppProperties appProperties, AuthTokenProvider authTokenProvider, AuthenticationManager authenticationManager, UserRefreshTokenRepository userRefreshTokenRepository) {
        this.appProperties = appProperties;
        this.authTokenProvider = authTokenProvider;
        this.authenticationManager = authenticationManager;
        this.userRefreshTokenRepository = userRefreshTokenRepository;
    }

    @PostMapping("/api/v1/auth/login")
    public ApiResponse login(HttpServletRequest request, HttpServletResponse response, @RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getId(), authRequest.getPassword()));

        String userId = authRequest.getId();
        SecurityContextHolder.getContext().setAuthentication(authentication);

        Date now = new Date();
        AuthToken accessToken = authTokenProvider.createAuthToken(userId, new Date(now.getTime() + appProperties.getAuth().getTokenExpiry()));

        long refreshTokenExpiry = appProperties.getAuth().getRefreshTokenExpiry();
        AuthToken refreshToken = authTokenProvider.createAuthToken(appProperties.getAuth().getTokenSecret(), new Date(now.getTime() + refreshTokenExpiry));

        UserRefreshToken userRefreshToken = userRefreshTokenRepository.findByUserId(userId).orElseThrow();
        if (userRefreshToken == null) {
            userRefreshToken = new UserRefreshToken(userId, refreshToken.getToken());
            userRefreshTokenRepository.save(userRefreshToken);
        } else {
            userRefreshToken.updateRefreshToken(refreshToken.getToken());
        }

        int cookieMaxAge = (int) (refreshTokenExpiry / 60);
        CookieUtil.deleteCookie(request, response, REFRESH_TOKEN);
        CookieUtil.addCookie(response, REFRESH_TOKEN, refreshToken.getToken(), cookieMaxAge);

        return ApiResponse.success("token", accessToken.getToken());
    }

    @GetMapping("/api/v1/auth/refresh")
    public ApiResponse refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String accessToken = HeaderUtil.getAccessToken(request);
        AuthToken authToken = authTokenProvider.convertAuthToken(accessToken);
        if (!authToken.validate()) {
            return ApiResponse.invalidAccessToken();
        }

        Claims claims = authToken.getExpiredTokenClaims();
        if (claims == null) {
            return ApiResponse.notExpiredTokenYet();
        }

        String userId = claims.getSubject();

        String refreshToken = CookieUtil.getCookie(request, REFRESH_TOKEN)
                .map(Cookie::getValue)
                .orElse(null);
        AuthToken authRefreshToken = authTokenProvider.convertAuthToken(refreshToken);

        if (authRefreshToken.validate()) {
            return ApiResponse.invalidRefreshToken();
        }

        UserRefreshToken userRefreshToken = userRefreshTokenRepository.findByUserIdAndRefreshToken(userId, refreshToken).orElseThrow();
        if (userRefreshToken == null) {
            return ApiResponse.invalidRefreshToken();
        }

        Date now = new Date();
        AuthToken newAccessToken = authTokenProvider.createAuthToken(userId, new Date(now.getTime() + appProperties.getAuth().getTokenExpiry()));

        long validTime = authRefreshToken.getTokenClaims().getExpiration().getTime() - now.getTime();

        if (validTime <= THREE_DAYS_MSEC) {
            long refreshTokenExpiry = appProperties.getAuth().getRefreshTokenExpiry();

            authRefreshToken = authTokenProvider.createAuthToken(appProperties.getAuth().getTokenSecret(), new Date(now.getTime() + refreshTokenExpiry));

            userRefreshToken.updateRefreshToken(authRefreshToken.getToken());

            int cookieMaxAge = (int) (refreshTokenExpiry / 60);
            CookieUtil.deleteCookie(request, response, REFRESH_TOKEN);
            CookieUtil.addCookie(response, REFRESH_TOKEN, authRefreshToken.getToken(), cookieMaxAge);
        }

        return ApiResponse.success("token", newAccessToken.getToken());
    }
}

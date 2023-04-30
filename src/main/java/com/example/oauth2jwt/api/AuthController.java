package com.example.oauth2jwt.api;

import com.example.oauth2jwt.domain.*;
import com.example.oauth2jwt.dto.ApiResponse;
import com.example.oauth2jwt.dto.AuthRequest;
import com.example.oauth2jwt.global.auth.properties.AppProperties;
import com.example.oauth2jwt.global.auth.token.AuthToken;
import com.example.oauth2jwt.global.auth.token.AuthTokenProvider;
import com.example.oauth2jwt.global.utils.CookieUtil;
import com.example.oauth2jwt.global.utils.HeaderUtil;
import io.jsonwebtoken.Claims;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.Optional;

@RestController
public class AuthController {
    private final static long THREE_DAYS_MSEC = 60000;
    private final static String REFRESH_TOKEN = "refresh_token";

    private final AppProperties appProperties;
    private final AuthTokenProvider authTokenProvider;
    private final UserRefreshTokenRepository userRefreshTokenRepository;
    private final UserRepository userRepository;

    public AuthController(AppProperties appProperties, AuthTokenProvider authTokenProvider, UserRefreshTokenRepository userRefreshTokenRepository, UserRepository userRepository) {
        this.appProperties = appProperties;
        this.authTokenProvider = authTokenProvider;
        this.userRefreshTokenRepository = userRefreshTokenRepository;
        this.userRepository = userRepository;
    }

    @PostMapping("/api/v1/signup")
    public void signup(@RequestBody AuthRequest authRequest) {
        userRepository.save(new User(authRequest.getId(), "TEST", authRequest.getPassword() ,"EMAIL", "IMAGE", ProviderType.NONE));
    }

    @Transactional
    @PostMapping("/api/v1/auth/login")
    public ApiResponse login(HttpServletRequest request, HttpServletResponse response, @RequestBody AuthRequest authRequest) {
        User user = userRepository.findByEmail(authRequest.getId()).orElseThrow();
        if (!authRequest.getPassword().equals(user.getPassword())) {
            throw new IllegalArgumentException("");
        }

        String userId = authRequest.getId();

        Date now = new Date();
        AuthToken accessToken = authTokenProvider.createAuthToken(userId, new Date(now.getTime() + appProperties.getAuth().getTokenExpiry()));

        long refreshTokenExpiry = appProperties.getAuth().getRefreshTokenExpiry();
        AuthToken refreshToken = authTokenProvider.createAuthToken(appProperties.getAuth().getTokenSecret(), new Date(now.getTime() + refreshTokenExpiry));

        Optional<UserRefreshToken> optionalUserRefreshToken = userRefreshTokenRepository.findByUserId(userId);
        UserRefreshToken userRefreshToken;
        if (!optionalUserRefreshToken.isPresent()) {
            userRefreshToken = new UserRefreshToken(userId, refreshToken.getToken());
            userRefreshTokenRepository.save(userRefreshToken);
        } else {
            userRefreshToken = optionalUserRefreshToken.get();
            userRefreshToken.updateRefreshToken(refreshToken.getToken());
        }

        int cookieMaxAge = (int) (refreshTokenExpiry / 60);
        CookieUtil.deleteCookie(request, response, REFRESH_TOKEN);
        CookieUtil.addCookie(response, REFRESH_TOKEN, refreshToken.getToken(), cookieMaxAge);

        return ApiResponse.success("token", accessToken.getToken());
    }

    /*
    * 1. acessToken과 refreshToken 모두 만료 -> 에러발생, 재로그인
    * 2. acessToken은 만료이지만 refreshToken은 유효 -> refreshToken 검증하여 acessToken 재발근
    * 3. acessToken은 유효하지만, refreshToken은 만료 -> acessToken 검증하여 refreshToken 재발급
    * 4. acessToken과 refreshToken 모듀 유효 -> 정상처리
    */
    @Transactional
    @GetMapping("/api/v1/auth/refresh")
    public ApiResponse refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String accessToken = HeaderUtil.getAccessToken(request);
        AuthToken authToken = authTokenProvider.convertAuthToken(accessToken);

        if (authToken.validate()) {
            Claims claims = authToken.getExpiredTokenClaims();
            String userId = claims.getSubject();

            String refreshToken = CookieUtil.getCookie(request, REFRESH_TOKEN)
                    .map(Cookie::getValue)
                    .orElse(null);

            AuthToken authRefreshToken = authTokenProvider.convertAuthToken(refreshToken);

            if (!authRefreshToken.validate()) {
                UserRefreshToken userRefreshToken = userRefreshTokenRepository.findByUserIdAndRefreshToken(userId, refreshToken).orElseThrow();
                Date now = new Date();

                long refreshTokenExpiry = appProperties.getAuth().getRefreshTokenExpiry();

                authRefreshToken = authTokenProvider.createAuthToken(appProperties.getAuth().getTokenSecret(), new Date(now.getTime() + refreshTokenExpiry));

                userRefreshToken.updateRefreshToken(authRefreshToken.getToken());

                int cookieMaxAge = (int) (refreshTokenExpiry / 60);
                CookieUtil.deleteCookie(request, response, REFRESH_TOKEN);
                CookieUtil.addCookie(response, REFRESH_TOKEN, authRefreshToken.getToken(), cookieMaxAge);

                return ApiResponse.success(REFRESH_TOKEN, userRefreshToken.getRefreshToken());
            }

            return ApiResponse.success("success", "모두 정상");
        } else {
            String refreshToken = CookieUtil.getCookie(request, REFRESH_TOKEN)
                    .map(Cookie::getValue)
                    .orElse(null);

            AuthToken authRefreshToken = authTokenProvider.convertAuthToken(refreshToken);

            if (!authRefreshToken.validate()) {
                return ApiResponse.fail();
            }

            Claims claims = authToken.getExpiredTokenClaims();
            String userId = claims.getSubject();

            Date now = new Date();
            AuthToken newAccessToken = authTokenProvider.createAuthToken(userId, new Date(now.getTime() + appProperties.getAuth().getTokenExpiry()));

            return ApiResponse.success("token", newAccessToken.getToken());
        }
    }
}

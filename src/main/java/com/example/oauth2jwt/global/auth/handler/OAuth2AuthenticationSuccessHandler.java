package com.example.oauth2jwt.global.auth.handler;

import com.example.oauth2jwt.domain.ProviderType;
import com.example.oauth2jwt.domain.UserRefreshToken;
import com.example.oauth2jwt.domain.UserRefreshTokenRepository;
import com.example.oauth2jwt.global.auth.info.OAuth2UserInfo;
import com.example.oauth2jwt.global.auth.info.OAuth2UserInfoFactory;
import com.example.oauth2jwt.global.auth.properties.AppProperties;
import com.example.oauth2jwt.global.auth.repository.OAuth2AuthorizationRequestBasedOnCookieRepository;
import com.example.oauth2jwt.global.auth.token.AuthToken;
import com.example.oauth2jwt.global.auth.token.AuthTokenProvider;
import com.example.oauth2jwt.global.utils.CookieUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.Optional;

import static com.example.oauth2jwt.global.auth.repository.OAuth2AuthorizationRequestBasedOnCookieRepository.REDIRECT_URI_PARAM_COOKIE_NAME;
import static com.example.oauth2jwt.global.auth.repository.OAuth2AuthorizationRequestBasedOnCookieRepository.REFRESH_TOKEN;

public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AuthTokenProvider tokenProvider;
    private final AppProperties appProperties;
    private final UserRefreshTokenRepository userRefreshTokenRepository;
    private final OAuth2AuthorizationRequestBasedOnCookieRepository authorizationRequestBasedOnCookieRepository;

    public OAuth2AuthenticationSuccessHandler(AuthTokenProvider tokenProvider, AppProperties appProperties, UserRefreshTokenRepository userRefreshTokenRepository,
                                              OAuth2AuthorizationRequestBasedOnCookieRepository authorizationRequestBasedOnCookieRepository) {
        this.tokenProvider = tokenProvider;
        this.appProperties = appProperties;
        this.userRefreshTokenRepository = userRefreshTokenRepository;
        this.authorizationRequestBasedOnCookieRepository = authorizationRequestBasedOnCookieRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            return;
        }

        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<String> redirectUri = CookieUtil.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        if (redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new IllegalArgumentException("");
        }

        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

        OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
        ProviderType providerType = ProviderType.valueOf(authToken.getAuthorizedClientRegistrationId().toUpperCase());

        OidcUser user = (OidcUser) authentication.getPrincipal();
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(providerType, user.getAttributes());

        Date now = new Date();
        AuthToken accessToken = tokenProvider.createAuthToken(userInfo.getEmail(), new Date(now.getTime() + appProperties.getAuth().getTokenExpiry()));

        long refreshTokenExpiry = appProperties.getAuth().getRefreshTokenExpiry();

        AuthToken refreshToken = tokenProvider.createAuthToken(appProperties.getAuth().getTokenSecret(), new Date(now.getTime() + refreshTokenExpiry));

        UserRefreshToken userRefreshToken = userRefreshTokenRepository.findByUserId(userInfo.getId()).orElseThrow();
        if (userRefreshToken != null) {
            userRefreshToken.updateRefreshToken(refreshToken.getToken());
        } else {
            userRefreshToken = new UserRefreshToken(userInfo.getId(), refreshToken.getToken());
            userRefreshTokenRepository.save(userRefreshToken);
        }

        int cookieMaxAge = (int) (refreshTokenExpiry / 60);

        CookieUtil.deleteCookie(request, response, REFRESH_TOKEN);
        CookieUtil.addCookie(response, REFRESH_TOKEN, refreshToken.getToken(), cookieMaxAge);

        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("token", accessToken.getToken())
                .build().toUriString();
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);

        return appProperties.getOAuth2().getAuthorizedRedirectUris()
                .stream()
                .anyMatch(authorizedRedirectUri -> {
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    if (authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost()) && authorizedURI.getPort() == clientRedirectUri.getPort()) {
                        return true;
                    }
                    return false;
                });
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        authorizationRequestBasedOnCookieRepository.removeAuthorizationRequestCookies(request, response);
    }


}

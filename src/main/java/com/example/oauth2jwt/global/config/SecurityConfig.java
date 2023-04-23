package com.example.oauth2jwt.global.config;

import com.example.oauth2jwt.domain.UserRefreshTokenRepository;
import com.example.oauth2jwt.global.auth.exception.RestAuthenticationEntryPoint;
import com.example.oauth2jwt.global.auth.filter.TokenAuthenticationFilter;
import com.example.oauth2jwt.global.auth.handler.OAuth2AuthenticationFailureHandler;
import com.example.oauth2jwt.global.auth.handler.OAuth2AuthenticationSuccessHandler;
import com.example.oauth2jwt.global.auth.handler.TokenAccessDeniedHandler;
import com.example.oauth2jwt.global.auth.properties.AppProperties;
import com.example.oauth2jwt.global.auth.repository.OAuth2AuthorizationRequestBasedOnCookieRepository;
import com.example.oauth2jwt.global.auth.service.CustomOAuth2UserService;
import com.example.oauth2jwt.global.auth.token.AuthTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsUtils;

@Configuration
public class SecurityConfig {
    private final AppProperties appProperties;
    private final AuthTokenProvider authTokenProvider;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final TokenAccessDeniedHandler tokenAccessDeniedHandler;
    private final UserRefreshTokenRepository userRefreshTokenRepository;

    public SecurityConfig(AppProperties appProperties, AuthTokenProvider authTokenProvider, CustomOAuth2UserService customOAuth2UserService, TokenAccessDeniedHandler tokenAccessDeniedHandler, UserRefreshTokenRepository userRefreshTokenRepository) {
        this.appProperties = appProperties;
        this.authTokenProvider = authTokenProvider;
        this.customOAuth2UserService = customOAuth2UserService;
        this.tokenAccessDeniedHandler = tokenAccessDeniedHandler;
        this.userRefreshTokenRepository = userRefreshTokenRepository;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .exceptionHandling()
                .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                .accessDeniedHandler(tokenAccessDeniedHandler)
                .and()
                .authorizeRequests()
                .requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
                .antMatchers("/api/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .authorizationEndpoint()
                .baseUri("/oauth2/authorization")
                .authorizationRequestRepository(oAuth2AuthorizationRequestBasedOnCookieRepository())
                .and()
                .redirectionEndpoint()
                .baseUri("/*/oauth2/code/*")
                .and()
                .userInfoEndpoint()
                .userService(customOAuth2UserService)
                .and()
                .successHandler(oAuth2AuthenticationSuccessHandler())
                .failureHandler(oAuth2AuthenticationFailureHandler());

        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter(authTokenProvider);
    }

    @Bean
    public OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository() {
        return new OAuth2AuthorizationRequestBasedOnCookieRepository();
    }

    @Bean
    public OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler(authTokenProvider, appProperties, userRefreshTokenRepository, oAuth2AuthorizationRequestBasedOnCookieRepository());
    }

    @Bean
    public OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler() {
        return new OAuth2AuthenticationFailureHandler(oAuth2AuthorizationRequestBasedOnCookieRepository());
    }

//    @Bean
//    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
//        UrlBasedCorsConfigurationSource corsConfigurationSource = new UrlBasedCorsConfigurationSource();
//
//        CorsConfiguration corsConfiguration = new CorsConfiguration();
//        corsConfiguration.setAllowedHeaders(Arrays.asList(corsProperties.getAllowedHeaders().split(",")));
//        corsConfiguration.setAllowedMethods(Arrays.asList(corsProperties.getAllowedMethods().split(",")));
//        corsConfiguration.setAllowedOrigins(Arrays.asList(corsProperties.getAllowedOrigins().split(",")));
//        corsConfiguration.setAllowCredentials(true);
//        corsConfiguration.setMaxAge(corsConfiguration.getMaxAge());
//
//        corsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);
//        return corsConfigurationSource;
//    }
}

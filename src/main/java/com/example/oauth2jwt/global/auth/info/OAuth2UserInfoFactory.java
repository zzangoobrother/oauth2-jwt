package com.example.oauth2jwt.global.auth.info;

import com.example.oauth2jwt.domain.ProviderType;
import com.example.oauth2jwt.global.auth.info.impl.KakaoOAuth2UserInfo;
import com.example.oauth2jwt.global.auth.info.impl.NaverOAuth2UserInfo;

import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(ProviderType providerType, Map<String, Object> attributes) {
        switch (providerType) {
            case KAKAO -> {
                return new KakaoOAuth2UserInfo(attributes);
            }
            case NAVER -> {
                return new NaverOAuth2UserInfo(attributes);
            }
            default -> throw new IllegalArgumentException("");
        }
    }
}

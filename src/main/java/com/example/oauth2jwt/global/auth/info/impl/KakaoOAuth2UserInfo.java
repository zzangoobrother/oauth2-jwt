package com.example.oauth2jwt.global.auth.info.impl;

import com.example.oauth2jwt.global.auth.info.OAuth2UserInfo;

import java.util.Map;

public class KakaoOAuth2UserInfo extends OAuth2UserInfo {
    public KakaoOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return attributes.get("id").toString();
    }

    @Override
    public String getEmail() {
        return attributes.get("account_email").toString();
    }

    @Override
    public String getUsername() {
        Map<String, Object> response = (Map<String, Object>) attributes.get("properties");

        if (response == null) {
            return null;
        }

        return (String) response.get("nickname");
    }

    @Override
    public String getImageUrl() {
        Map<String, Object> response = (Map<String, Object>) attributes.get("properties");

        if (response == null) {
            return null;
        }

        return (String) response.get("thumbnail_image");
    }
}

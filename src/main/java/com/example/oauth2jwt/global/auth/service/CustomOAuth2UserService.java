package com.example.oauth2jwt.global.auth.service;

import com.example.oauth2jwt.domain.ProviderType;
import com.example.oauth2jwt.domain.User;
import com.example.oauth2jwt.domain.UserRepository;
import com.example.oauth2jwt.global.auth.exception.OAuthProviderMissMatchException;
import com.example.oauth2jwt.global.auth.info.OAuth2UserInfo;
import com.example.oauth2jwt.global.auth.info.OAuth2UserInfoFactory;
import com.example.oauth2jwt.global.auth.model.UserPrincipal;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        try {
            return process(userRequest, oAuth2User);
        } catch (Exception e) {
            throw new InternalAuthenticationServiceException(e.getMessage(), e.getCause());
        }
    }

    private OAuth2User process(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        ProviderType providerType = ProviderType.valueOf(userRequest.getClientRegistration().getRegistrationId().toUpperCase());

        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(providerType, oAuth2User.getAttributes());
        User user = userRepository.findByEmail(oAuth2User.getName()).orElseThrow();

        if (user != null) {
            if (providerType != user.getProviderType()) {
                throw new OAuthProviderMissMatchException("Looks like you're signed up with " + providerType + " account. Please use your " + user.getProviderType() + " account to login.");
            }
            updateUser(user, oAuth2UserInfo);
        } else {
            user = createUser(oAuth2UserInfo, providerType);
        }

        return UserPrincipal.of(user);
    }

    private User updateUser(User user, OAuth2UserInfo oAuth2UserInfo) {
        if (oAuth2UserInfo.getEmail() != null && user.getEmail().equals(oAuth2UserInfo.getEmail())) {
            user.updateEmail(oAuth2UserInfo.getEmail());
        }

        if (oAuth2UserInfo.getImageUrl() != null && user.getProfileImageUrl().equals(oAuth2UserInfo.getImageUrl())) {
            user.updateProfileImageUrl(oAuth2UserInfo.getImageUrl());
        }

        return user;
    }

    private User createUser(OAuth2UserInfo oAuth2UserInfo, ProviderType providerType) {
        User user = new User(
                oAuth2UserInfo.getUsername(),
                oAuth2UserInfo.getUsername(),
                oAuth2UserInfo.getEmail(),
                oAuth2UserInfo.getImageUrl(),
                providerType
        );

        return userRepository.save(user);
    }
}

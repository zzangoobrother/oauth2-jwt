package com.example.oauth2jwt.domain;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
@Table(name = "USER")
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "login_id", unique = true)
    private String loginId;

    @Column(name = "username", length = 100)
    private String username;

    @Column(name = "password", length = 128)
    private String password;

    @Column(name = "email", length = 512, unique = true)
    private String email;

    @Column(name = "profile_image_url", length = 512)
    private String profileImageUrl;

    @Column(name = "type", length = 20)
    @Enumerated(EnumType.STRING)
    private ProviderType providerType;

    public User(String loginId, String username, String password, String email, String profileImageUrl, ProviderType providerType) {
        this.loginId = loginId;
        this.username = username;
        this.password = password;
        this.email = email;
        this.profileImageUrl = profileImageUrl;
        this.providerType = providerType;
    }

    public User(String loginId, String username, String email, String profileImageUrl, ProviderType providerType) {
        this.loginId = loginId;
        this.username = username;
        this.email = email;
        this.profileImageUrl = profileImageUrl;
        this.providerType = providerType;
    }

    public void updateEmail(String email) {
        this.email = email;
    }

    public void updateProfileImageUrl(String imageUrl) {
        this.profileImageUrl = imageUrl;
    }
}

package com.example.oauth2jwt.application;

import com.example.oauth2jwt.domain.User;
import com.example.oauth2jwt.domain.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User getUser(String email) {
        return userRepository.findByEmail(email).orElseThrow();
    }
}

package com.example.oauth2jwt.api;

import com.example.oauth2jwt.application.UserService;
import com.example.oauth2jwt.dto.ApiResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/api/v1/users")
    public ApiResponse getUser() {
        User principal = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        return ApiResponse.success("user", userService.getUser(principal.getUsername()));
    }
}

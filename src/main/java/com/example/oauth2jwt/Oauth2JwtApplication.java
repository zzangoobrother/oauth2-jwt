package com.example.oauth2jwt;

import com.example.oauth2jwt.global.auth.properties.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({
        AppProperties.class
})
public class Oauth2JwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2JwtApplication.class, args);
    }

}

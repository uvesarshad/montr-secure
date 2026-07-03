package com.example.vuln.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * corpus: jvm-vuln — Spring Security wiring. DO NOT DEPLOY.
 * Planted: A05:2021 CSRF protection globally disabled.
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // A05:2021 — CSRF protection turned off for the whole application.
        http.csrf().disable();
        return http.build();
    }
}

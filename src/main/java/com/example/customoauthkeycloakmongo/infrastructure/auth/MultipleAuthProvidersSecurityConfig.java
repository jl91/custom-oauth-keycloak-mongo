package com.example.customoauthkeycloakmongo.infrastructure.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class MultipleAuthProvidersSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(
            final HttpSecurity http,
            final CustomAuthenticationProvider customAuthProvider
    ) throws Exception {

        final var httpSecurity = http
                .authorizeRequests()
                .antMatchers("/api/health-check").permitAll()
                .anyRequest().authenticated()
                .and();

        httpSecurity.authenticationProvider(customAuthProvider);
        httpSecurity.httpBasic();

        return httpSecurity.build();
    }

}

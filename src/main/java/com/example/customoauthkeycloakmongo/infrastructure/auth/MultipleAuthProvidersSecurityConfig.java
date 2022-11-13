package com.example.customoauthkeycloakmongo.infrastructure.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class MultipleAuthProvidersSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(
            final HttpSecurity http,
            final AuthTokenFilter authTokenFilter
    ) throws Exception {

        final var httpSecurity = http
                .cors().disable()
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/api/health-check").permitAll()
                .anyRequest().authenticated()
                .and();

        httpSecurity.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//        httpSecurity.authenticationProvider(customAuthProvider);

        httpSecurity.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }

}

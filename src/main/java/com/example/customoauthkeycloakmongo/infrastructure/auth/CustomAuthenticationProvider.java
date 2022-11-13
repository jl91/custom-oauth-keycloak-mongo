package com.example.customoauthkeycloakmongo.infrastructure.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Slf4j
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final var username = authentication.getName();
        final var password = authentication.getCredentials().toString();

        log.info("Username {} password {} ", username, password);

        if (
                "admin".equals(username)
                        && "admin".equals(password)
        ) {

            return new UsernamePasswordAuthenticationToken(
                    username,
                    password,
                    List.of(
                            new GrantedAuthority() {
                                @Override
                                public String getAuthority() {
                                    return "master";
                                }
                            }
                    )
            );
        }

        throw new BadCredentialsException("External system authentication failed");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}

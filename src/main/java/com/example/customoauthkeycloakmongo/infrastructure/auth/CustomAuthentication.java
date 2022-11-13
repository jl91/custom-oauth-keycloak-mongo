package com.example.customoauthkeycloakmongo.infrastructure.auth;

import com.nimbusds.jwt.JWTParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Component
@Slf4j
public class CustomAuthentication {

    public Authentication authenticate(
            final HttpServletRequest request
    ) throws AuthenticationException {

        final var authorizationHeader = request.getHeader("Authorization");

        if (
                authorizationHeader == null
                        || authorizationHeader.isEmpty()
                        || authorizationHeader.isBlank()
        ) {
            throw new BadCredentialsException("Authorization header not provided");
        }

        if (!isValidAuthorizationToken(authorizationHeader)) {
            throw new BadCredentialsException("Invalid bearer token");
        }

        if (!isValidJWTToken(authorizationHeader)) {
            throw new BadCredentialsException("Invalid jwt token");
        }

        return new UsernamePasswordAuthenticationToken(
                "teste",
                "",
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

    private boolean isValidAuthorizationToken(
            final String header
    ) {
        final var lowerCaseHeader = header.toLowerCase();

        final var pieces = lowerCaseHeader.split(" ");

        if (pieces.length != 2) {
            return false;
        }

        if (!pieces[0].equals("bearer")) {
            return false;
        }

        return pieces[1].length() > 0;
    }

    private boolean isValidJWTToken(
            final String header
    ) {
        final var pieces = header.split(" ");

        final var token = pieces[1];

        try {
            JWTParser.parse(token);
            return true;
        } catch (Throwable throwable) {
            log.error("Error on try do decode token {}, Exception: {}", token, throwable);
            return false;
        }
    }

}

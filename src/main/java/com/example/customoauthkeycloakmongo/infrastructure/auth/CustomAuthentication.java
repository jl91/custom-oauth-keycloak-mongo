package com.example.customoauthkeycloakmongo.infrastructure.auth;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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

        final var tokenType = getTokenType(authorizationHeader);

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

    private String extractTokenFromHeader(
            final String header
    ) {
        final var pieces = header.split(" ");
        return pieces[1];
    }

    private JWT decodeToken(final String token) {
        try {
            return JWTParser.parse(token);
        } catch (Throwable throwable) {
            log.error("Error on try to decode token {}, Exception: {}", token, throwable);
            return null;
        }

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
        final var token = extractTokenFromHeader(header);

        return decodeToken(token) != null;
    }

    private String getTokenType(
            final String header
    ) {
        final var token = extractTokenFromHeader(header);
        final var jwt = decodeToken(token);

        try {
            Map<String, Object> headers = new LinkedHashMap<>(jwt.getHeader().toJSONObject());
            Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();

            if (claims.containsKey("iss")) {
                return "mongo";
            }

            return "keycloak";

        } catch (Throwable throwable) {
            log.error("Error on try to parse token Claims token {}, Exception: {}", token, throwable);
        }

        return "";
    }

}

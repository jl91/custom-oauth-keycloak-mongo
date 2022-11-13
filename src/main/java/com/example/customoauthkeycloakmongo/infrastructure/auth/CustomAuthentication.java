package com.example.customoauthkeycloakmongo.infrastructure.auth;

import com.example.customoauthkeycloakmongo.infrastructure.database.mongo.repositories.FakeAuthTokenMongoRepository;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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

    private final static String MONGO_TOKEN_TYPE = "mongo-token-type";
    private final static String KEYCLOAK_TOKEN_TYPE = "keycloak-token-type";

    private FakeAuthTokenMongoRepository fakeAuthTokenMongoRepository;


    @Autowired
    CustomAuthentication(
            final FakeAuthTokenMongoRepository fakeAuthTokenMongoRepository
    ) {
        this.fakeAuthTokenMongoRepository = fakeAuthTokenMongoRepository;
    }


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

        if (tokenType.equals(MONGO_TOKEN_TYPE)) {
            return getMongoAuthentication(
                    authorizationHeader
            );
        }

        return getKeycloakAuthentication();
    }


    private UsernamePasswordAuthenticationToken getMongoAuthentication(
            final String token
    ) {

        final var claims = getClaims(token);

        if (!claims.containsKey("iss")) {
            log.error(" ISS not found on JWT ", token);
            throw new BadCredentialsException("Invalid Token");
        }

        final var iss = (String) claims.get("iss");

        final var mongoDocument = this.fakeAuthTokenMongoRepository.findOnByToken(iss);

        if (mongoDocument.isEmpty()) {
            log.error("Token {} not found on mongo db ", token);
            throw new BadCredentialsException("Invalid Token");
        }

        final var tokenDocument = mongoDocument.get();

        return new UsernamePasswordAuthenticationToken(
                tokenDocument.get_id(),
                tokenDocument.getToken(),
                List.of(
                        (GrantedAuthority) () -> "master"
                )
//                List.of(
//                        new GrantedAuthority() {
//                            @Override
//                            public String getAuthority() {
//                                return "master";
//                            }
//                        }
//                )
        );
    }


    private UsernamePasswordAuthenticationToken getKeycloakAuthentication() {
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
//            Map<String, Object> headers = new LinkedHashMap<>(jwt.getHeader().toJSONObject());
            Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();

            if (claims.containsKey("iss")) {
                return MONGO_TOKEN_TYPE;
            }

            return KEYCLOAK_TOKEN_TYPE;

        } catch (Throwable throwable) {
            log.error("Error on try to parse token Claims token {}, Exception: {}", token, throwable);
        }

        return "";
    }

    private Map<String, Object> getClaims(
            final String header
    ) {
        final var token = extractTokenFromHeader(header);
        final var jwt = decodeToken(token);

        try {
//            Map<String, Object> headers = new LinkedHashMap<>(jwt.getHeader().toJSONObject());
            return jwt.getJWTClaimsSet().getClaims();

        } catch (Throwable throwable) {
            log.error("Error on try to parse token Claims token {}, Exception: {}", token, throwable);
        }

        return null;
    }

}

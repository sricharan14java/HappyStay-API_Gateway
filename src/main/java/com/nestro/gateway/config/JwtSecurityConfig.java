package com.nestro.gateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Configuration
public class JwtSecurityConfig {

    @Value("${nestro.security.jwt.secret-key}")
    private String secretKey;

    @Value("${nestro.security.jwt.issuer}")
    private String issuer;

    /*
     * Creates and validates the JWT secret key.
     *
     * The secret must:
     * 1. Exist
     * 2. Be valid Base64
     * 3. Contain at least 32 bytes
     * 4. Be canonical Base64
     */
    @Bean
    public SecretKey jwtSecretKey() {

        if (secretKey == null || secretKey.isBlank()) {

            throw new IllegalStateException(
                    "JWT secret key is missing. " +
                            "Please configure 'nestro.security.jwt.secret-key'"
            );
        }

        final byte[] decodedKey;

        try {

            decodedKey = Base64.getDecoder().decode(secretKey);

        } catch (IllegalArgumentException e) {

            throw new IllegalStateException(
                    "Invalid JWT secret key. " +
                            "The key must be a valid Base64-encoded value.",
                    e
            );
        }

        /*
         * HS256 requires a minimum of 256 bits = 32 bytes.
         */
        if (decodedKey.length < 32) {

            throw new IllegalStateException(
                    "Invalid JWT secret key. " +
                            "HS256 requires a minimum 256-bit (32-byte) secret key."
            );
        }

        /*
         * Verify canonical Base64 format.
         *
         * This makes sure that characters such as
         * the final '=' padding have not been removed.
         */
        String canonicalBase64 =
                Base64.getEncoder().encodeToString(decodedKey);

        if (!secretKey.equals(canonicalBase64)) {

            throw new IllegalStateException(
                    "Invalid JWT secret key. " +
                            "The secret must be a canonical Base64-encoded value."
            );
        }

        return new SecretKeySpec(
                decodedKey,
                "HmacSHA256"
        );
    }

    /*
     * Decoder used by Gateway to validate JWT access tokens.
     */
    @Bean
    @Primary
    public JwtDecoder jwtDecoder(
            SecretKey jwtSecretKey) {

        NimbusJwtDecoder jwtDecoder =
                NimbusJwtDecoder
                        .withSecretKey(jwtSecretKey)
                        .macAlgorithm(MacAlgorithm.HS256)
                        .build();

        /*
         * Validate JWT issuer.
         */
        OAuth2TokenValidator<Jwt> issuerValidator =
                JwtValidators.createDefaultWithIssuer(
                        issuer
                );

        /*
         * Gateway accepts ONLY access tokens.
         */
        OAuth2TokenValidator<Jwt> accessTokenValidator =
                jwt -> {

                    String tokenType =
                            jwt.getClaimAsString("tokenType");

                    if (!"access".equals(tokenType)) {

                        return OAuth2TokenValidatorResult.failure(
                                new OAuth2Error(
                                        "invalid_token",
                                        "Token is not an access token",
                                        null
                                )
                        );
                    }

                    return OAuth2TokenValidatorResult.success();
                };

        /*
         * Both validations must pass:
         *
         * 1. Issuer validation
         * 2. Access-token validation
         */
        jwtDecoder.setJwtValidator(
                new DelegatingOAuth2TokenValidator<>(
                        issuerValidator,
                        accessTokenValidator
                )
        );

        return jwtDecoder;
    }
}
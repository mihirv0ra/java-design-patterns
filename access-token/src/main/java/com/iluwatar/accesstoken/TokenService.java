/*
 * This project is licensed under the MIT license. Module model-view-viewmodel is using ZK framework
 * licensed under LGPL (see lgpl-3.0.txt).
 *
 * The MIT License
 * Copyright © 2014-2022 Ilkka Seppälä
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.iluwatar.accesstoken;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service that issues and validates signed tokens. The implementation uses a simple HMAC signature and
 * encodes the token payload using base64-url. The payload structure is intentionally easy to inspect so
 * that microservices can extract the claims without contacting the authorization server.
 */
public class TokenService {

  private static final Logger LOGGER = LoggerFactory.getLogger(TokenService.class);
  private static final String HMAC_ALGORITHM = "HmacSHA256";
  private static final String FIELD_SEPARATOR = "|";

  private final Clock clock;
  private final SecretKeySpec secretKey;

  public TokenService(String secret, Clock clock) {
    this.clock = clock;
    this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
  }

  /**
   * Generates a signed access token containing the provided claims.
   */
  public String generateToken(String subject, Set<String> scopes, Duration timeToLive) {
    var issuedAt = clock.instant();
    var expiresAt = issuedAt.plus(timeToLive);
    var serializedScopes = scopes.stream().sorted().collect(Collectors.joining(","));
    var payload = subject + FIELD_SEPARATOR + issuedAt.toEpochMilli() + FIELD_SEPARATOR
        + expiresAt.toEpochMilli() + FIELD_SEPARATOR + serializedScopes;
    var encodedPayload = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(payload.getBytes(StandardCharsets.UTF_8));
    var signature = Base64.getUrlEncoder().withoutPadding().encodeToString(sign(encodedPayload));
    return encodedPayload + '.' + signature;
  }

  /**
   * Parses a token and verifies its signature. Returns an {@link Optional#empty()} when the token is
   * malformed or the signature check fails.
   */
  public Optional<TokenClaims> parse(String token) {
    if (token == null || token.isBlank()) {
      return Optional.empty();
    }

    var segments = token.split("\\.");
    if (segments.length != 2) {
      LOGGER.warn("Token does not contain two segments");
      return Optional.empty();
    }

    var payload = segments[0];
    var providedSignature = decodeUrlSafe(segments[1]);
    var expectedSignature = sign(payload);

    if (providedSignature.isEmpty()) {
      return Optional.empty();
    }

    if (!MessageDigest.isEqual(providedSignature.get(), expectedSignature)) {
      LOGGER.warn("Token signature mismatch");
      return Optional.empty();
    }

    return decodeClaims(payload);
  }

  private Optional<TokenClaims> decodeClaims(String encodedPayload) {
    try {
      var decodedPayload = new String(Base64.getUrlDecoder().decode(encodedPayload),
          StandardCharsets.UTF_8);
      var fields = decodedPayload.split("\\|", -1);
      if (fields.length != 4) {
        LOGGER.warn("Token payload did not contain expected number of fields");
        return Optional.empty();
      }

      var subject = fields[0];
      var issuedAt = Instant.ofEpochMilli(Long.parseLong(fields[1]));
      var expiresAt = Instant.ofEpochMilli(Long.parseLong(fields[2]));
      var scopeField = fields[3];
      Set<String> scopes;
      if (scopeField.isEmpty()) {
        scopes = Set.of();
      } else {
        scopes = Arrays.stream(scopeField.split(","))
            .collect(Collectors.toCollection(LinkedHashSet::new));
      }
      return Optional.of(new TokenClaims(subject, scopes, issuedAt, expiresAt));
    } catch (IllegalArgumentException e) {
      LOGGER.warn("Failed to decode token payload", e);
      return Optional.empty();
    }
  }

  private byte[] sign(String data) {
    try {
      var mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(secretKey);
      return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Could not sign token", e);
    }
  }

  private Optional<byte[]> decodeUrlSafe(String data) {
    try {
      return Optional.of(Base64.getUrlDecoder().decode(data));
    } catch (IllegalArgumentException ex) {
      LOGGER.warn("Failed to decode signature", ex);
      return Optional.empty();
    }
  }
}

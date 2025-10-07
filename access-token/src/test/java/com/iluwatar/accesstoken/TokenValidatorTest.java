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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import org.junit.jupiter.api.Test;

class TokenValidatorTest {

  private static final Instant ISSUED_AT = Instant.parse("2024-01-01T00:00:00Z");
  private final Clock clock = Clock.fixed(ISSUED_AT, ZoneOffset.UTC);
  private final TokenService tokenService = new TokenService("secret", clock);

  @Test
  void shouldReturnClaimsForValidToken() {
    var validator = new TokenValidator(tokenService, clock);
    var token = tokenService.generateToken("client", Set.of("orders:read"), Duration.ofMinutes(5));

    var claims = validator.validate(token).orElseThrow();

    assertEquals("client", claims.subject());
    assertTrue(claims.hasScope("orders:read"));
  }

  @Test
  void shouldThrowWhenScopeMissing() {
    var validator = new TokenValidator(tokenService, clock);
    var token = tokenService.generateToken("client", Set.of("orders:read"), Duration.ofMinutes(5));

    assertThrows(AccessDeniedException.class, () -> validator.requireScope(token, "billing:charge"));
  }

  @Test
  void shouldReturnEmptyWhenExpired() {
    var token = tokenService.generateToken("client", Set.of("orders:read"), Duration.ZERO);
    var later = Clock.fixed(ISSUED_AT.plusSeconds(1), ZoneOffset.UTC);
    var validator = new TokenValidator(tokenService, later);

    assertTrue(validator.validate(token).isEmpty());
  }
}

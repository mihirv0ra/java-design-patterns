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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AuthorizationServerTest {

  private final AdjustableClock clock = new AdjustableClock(
      Instant.parse("2024-01-01T00:00:00Z"), ZoneOffset.UTC);
  private final TokenService tokenService = new TokenService("secret", clock);
  private final AuthorizationServer authorizationServer =
      new AuthorizationServer(tokenService, Duration.ofMinutes(5), Duration.ofHours(1), clock);
  private final TokenValidator validator = new TokenValidator(tokenService, clock);

  @Test
  void shouldIssueAndRefreshTokens() {
    var pair = authorizationServer.issueToken("client", Set.of("orders:read", "inventory:write"));
    var claims = validator.validate(pair.accessToken()).orElseThrow();

    assertEquals("client", claims.subject());
    assertEquals(Set.of("inventory:write", "orders:read"), claims.scopes());

    clock.advance(Duration.ofMinutes(1));
    var refreshed = authorizationServer.refreshAccessToken(pair.refreshToken()).orElseThrow();
    var refreshedClaims = validator.validate(refreshed).orElseThrow();

    assertEquals("client", refreshedClaims.subject());
    assertTrue(refreshedClaims.expiresAt().isAfter(clock.instant()));
  }

  @Test
  void shouldInvalidateExpiredRefreshToken() {
    var pair = authorizationServer.issueToken("client", Set.of("orders:read"));

    clock.advance(Duration.ofHours(2));

    assertTrue(authorizationServer.refreshAccessToken(pair.refreshToken()).isEmpty());
  }

  private static class AdjustableClock extends Clock {

    private Instant instant;
    private final ZoneOffset zone;

    private AdjustableClock(Instant instant, ZoneOffset zone) {
      this.instant = instant;
      this.zone = zone;
    }

    @Override
    public ZoneOffset getZone() {
      return zone;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
      return new AdjustableClock(instant, zone instanceof ZoneOffset offset ? offset : ZoneOffset.UTC);
    }

    @Override
    public Instant instant() {
      return instant;
    }

    private void advance(Duration duration) {
      instant = instant.plus(duration);
    }
  }
}

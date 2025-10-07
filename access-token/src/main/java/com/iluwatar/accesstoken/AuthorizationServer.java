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

import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Issues access tokens and refresh tokens. The authorization server authenticates the caller (omitted
 * in the example) and produces signed tokens for resource servers to validate.
 */
public class AuthorizationServer {

  private final TokenService tokenService;
  private final Duration accessTokenTtl;
  private final Duration refreshTokenTtl;
  private final Clock clock;
  private final Map<String, RefreshTokenInfo> refreshTokens = new ConcurrentHashMap<>();

  public AuthorizationServer(TokenService tokenService, Duration accessTokenTtl,
      Duration refreshTokenTtl, Clock clock) {
    this.tokenService = tokenService;
    this.accessTokenTtl = accessTokenTtl;
    this.refreshTokenTtl = refreshTokenTtl;
    this.clock = clock;
  }

  /**
   * Issues an access token and a refresh token for the authenticated principal.
   */
  public TokenPair issueToken(String subject, Set<String> scopes) {
    var accessToken = tokenService.generateToken(subject, scopes, accessTokenTtl);
    var refreshToken = UUID.randomUUID().toString();
    refreshTokens.put(refreshToken,
        new RefreshTokenInfo(subject, Set.copyOf(scopes), clock.instant().plus(refreshTokenTtl)));
    return new TokenPair(accessToken, refreshToken);
  }

  /**
   * Uses the refresh token to obtain a new access token.
   */
  public Optional<String> refreshAccessToken(String refreshToken) {
    var info = refreshTokens.get(refreshToken);
    if (info == null) {
      return Optional.empty();
    }

    if (!info.isValidAt(clock.instant())) {
      refreshTokens.remove(refreshToken);
      return Optional.empty();
    }

    return Optional.of(tokenService.generateToken(info.subject(), info.scopes(), accessTokenTtl));
  }

  private record RefreshTokenInfo(String subject, Set<String> scopes, java.time.Instant expiresAt) {
    private boolean isValidAt(java.time.Instant instant) {
      return expiresAt.isAfter(instant);
    }
  }
}

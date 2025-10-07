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
import java.util.Optional;

/**
 * Validates incoming tokens on behalf of microservices. The validator checks that the token is well
 * formed, signed by the trusted authority, has not expired yet, and provides the required scope.
 */
public class TokenValidator {

  private final TokenService tokenService;
  private final Clock clock;

  public TokenValidator(TokenService tokenService, Clock clock) {
    this.tokenService = tokenService;
    this.clock = clock;
  }

  /**
   * Parses and validates a token. Returns an empty optional when the token is invalid or expired.
   */
  public Optional<TokenClaims> validate(String token) {
    return tokenService.parse(token)
        .filter(claims -> !claims.isExpired(clock.instant()));
  }

  /**
   * Ensures that the provided token is valid and contains the requested scope.
   */
  public TokenClaims requireScope(String token, String scope) {
    var claims = validate(token)
        .orElseThrow(() -> new AccessDeniedException("Token is invalid or expired"));
    if (!claims.hasScope(scope)) {
      throw new AccessDeniedException("Token is missing scope: " + scope);
    }
    return claims;
  }
}

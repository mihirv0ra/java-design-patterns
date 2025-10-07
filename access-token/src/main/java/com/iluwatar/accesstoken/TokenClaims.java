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

import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable representation of the claims embedded in an access token.
 */
public record TokenClaims(String subject, Set<String> scopes, Instant issuedAt, Instant expiresAt) {

  public TokenClaims {
    Objects.requireNonNull(subject, "subject");
    Objects.requireNonNull(scopes, "scopes");
    Objects.requireNonNull(issuedAt, "issuedAt");
    Objects.requireNonNull(expiresAt, "expiresAt");
    this.scopes = Set.copyOf(scopes);
  }

  /**
   * Returns {@code true} when the token contains the provided scope.
   */
  public boolean hasScope(String scope) {
    return scopes.contains(scope);
  }

  /**
   * Indicates whether the token should be considered expired at the provided instant.
   */
  public boolean isExpired(Instant instant) {
    return !expiresAt.isAfter(instant);
  }
}

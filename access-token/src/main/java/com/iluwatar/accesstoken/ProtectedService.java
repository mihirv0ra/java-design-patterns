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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a microservice that trusts the authorization server. The service relies on the
 * {@link TokenValidator} to make authorization decisions instead of storing authentication state.
 */
public class ProtectedService {

  private static final Logger LOGGER = LoggerFactory.getLogger(ProtectedService.class);

  private final String serviceName;
  private final String requiredScope;
  private final TokenValidator tokenValidator;

  public ProtectedService(String serviceName, String requiredScope, TokenValidator tokenValidator) {
    this.serviceName = serviceName;
    this.requiredScope = requiredScope;
    this.tokenValidator = tokenValidator;
  }

  /**
   * Processes a request secured by an access token.
   */
  public String handleRequest(String token) {
    var claims = tokenValidator.requireScope(token, requiredScope);
    LOGGER.info("{} accepted request from subject {}", serviceName, claims.subject());
    return serviceName + " data for " + claims.subject();
  }
}

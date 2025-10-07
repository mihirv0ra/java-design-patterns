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
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The {@link App} class demonstrates how access tokens allow microservices to validate
 * incoming requests without maintaining their own authentication logic. An authorization server
 * issues tokens with scopes and expiry information, while individual services verify that
 * the presented token is still valid and grants the required permissions.
 */
public class App {

  private static final Logger LOGGER = LoggerFactory.getLogger(App.class);

  /**
   * Entry point of the example program.
   */
  public static void main(String[] args) {
    var clock = Clock.systemUTC();
    var tokenService = new TokenService("super-secret-signing-key", clock);
    var authorizationServer = new AuthorizationServer(
        tokenService, Duration.ofMinutes(5), Duration.ofHours(1), clock);
    var tokenValidator = new TokenValidator(tokenService, clock);

    var orderService = new ProtectedService("OrderService", "orders:read", tokenValidator);
    var billingService = new ProtectedService("BillingService", "billing:charge", tokenValidator);

    LOGGER.info("Requesting access token for reporting-service");
    var tokenPair = authorizationServer.issueToken("reporting-service", Set.of("orders:read"));

    LOGGER.info("Obtained access token for reporting-service");
    LOGGER.info("Order service response: {}", orderService.handleRequest(tokenPair.accessToken()));

    try {
      billingService.handleRequest(tokenPair.accessToken());
    } catch (AccessDeniedException ex) {
      LOGGER.warn("Billing request rejected: {}", ex.getMessage());
    }

    LOGGER.info("Refreshing access token using stored refresh token");
    authorizationServer.refreshAccessToken(tokenPair.refreshToken())
        .ifPresent(refreshed -> LOGGER.info("Refreshed token accepted by OrderService: {}",
            orderService.handleRequest(refreshed)));
  }
}

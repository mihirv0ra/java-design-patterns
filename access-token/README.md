---
title: "Access Token Pattern in Java: Secure Microservice Communication with JWT-style Tokens"
shortTitle: Access Token
description: "Implement the Access Token pattern in Java to decouple authentication from microservices, enforce scopes, and handle token refresh." 
category: Microservices
language: en
tag:
  - Authentication
  - Authorization
  - Microservices
  - Security
  - Cloud distributed
---

## Intent of the Access Token Design Pattern

The Access Token pattern externalizes authentication and authorization concerns to a dedicated authorization service. Microservices rely on the issued tokens to validate identity and permissions without embedding authentication logic in every service.

## Also known as

* Token-based security
* OAuth2 bearer tokens

## Detailed Explanation of the Access Token Pattern with Real-World Examples

Real-world example

> In a retail platform, a centralized authorization server issues OAuth2 access tokens to shopping cart, catalog, and payment services. Each microservice validates the token before serving a request, ensuring that the caller is authenticated and has the right scope, while the authorization server manages refresh tokens and token expiry.

In plain words

> Instead of letting every microservice maintain its own authentication logic, a separate server issues signed tokens. Microservices inspect the token to decide whether a call is allowed.

Wikipedia says

> In OAuth 2.0, a bearer token is issued by an authorization server and used by the client to access protected resources. Resource servers validate the token and grant or deny access accordingly.

## Programmatic Example of the Access Token Pattern in Java

The example demonstrates how an authorization server issues signed tokens that microservices can validate. Tokens include scopes that describe the operations the caller can perform and an expiration time that limits how long the token is valid. Refresh tokens allow clients to request a new access token without re-authenticating.

```java
var clock = Clock.systemUTC();
var tokenService = new TokenService("super-secret-signing-key", clock);
var authorizationServer = new AuthorizationServer(tokenService, Duration.ofMinutes(5), Duration.ofHours(1), clock);
var tokenValidator = new TokenValidator(tokenService, clock);
var orderService = new ProtectedService("OrderService", "orders:read", tokenValidator);

var tokenPair = authorizationServer.issueToken("reporting-service", Set.of("orders:read"));
orderService.handleRequest(tokenPair.accessToken()); // succeeds

// Billing service requires a different scope
var billingService = new ProtectedService("BillingService", "billing:charge", tokenValidator);
try {
  billingService.handleRequest(tokenPair.accessToken());
} catch (AccessDeniedException ex) {
  System.out.println("Billing request rejected: " + ex.getMessage());
}

var refreshed = authorizationServer.refreshAccessToken(tokenPair.refreshToken())
    .orElseThrow();
orderService.handleRequest(refreshed); // still valid after refresh
```

## When to Use the Access Token Pattern in Java

* When multiple microservices must trust the same authentication mechanism.
* When you want to enforce scopes and permissions without centralizing all logic in one gateway.
* When clients need long-running sessions that can be renewed via refresh tokens without storing credentials.

## Real-World Applications of the Access Token Pattern in Java

* Popular identity platforms such as Okta, Auth0, and Azure Active Directory rely on access tokens to
  secure third-party integrations and first-party microservices.
* Cloud providers like Google Cloud and AWS issue short-lived OAuth 2.0 tokens for service-to-service
  communication, ensuring workloads authenticate without long-term credentials.
* Enterprise API gateways frequently validate JWT access tokens to authorize partner applications and
  mobile clients.

## Benefits and Trade-offs of the Access Token Pattern

Benefits:

* Allows microservices to focus on business logic while relying on a shared authorization mechanism.
* Enables fine-grained access control with token scopes and claims.
* Supports stateless, scalable authentication since resource servers do not store session state.
* Refresh tokens improve usability by letting clients renew tokens without re-authenticating.

Trade-offs:

* Requires secure management of signing keys and HTTPS communication to protect tokens.
* Introduces complexity when implementing rotation and revocation of refresh tokens.
* Tokens must be carefully scoped to avoid privilege escalation.

## Related Java Design Patterns

* [Gateway](https://java-design-patterns.com/patterns/gateway/): Both patterns encapsulate
  external service access; Gateways can delegate authorization to token validation services.
* [Microservices API Gateway](https://java-design-patterns.com/patterns/microservices-api-gateway/):
  API gateways commonly validate access tokens before routing requests to downstream services.
* [Service Layer](https://java-design-patterns.com/patterns/service-layer/): Service boundaries often
  rely on access tokens to enforce cross-service security policies defined in the service layer.

## References and Credits

* [OAuth 2.0](https://oauth.net/2/)
* [JSON Web Tokens (JWT.io)](https://jwt.io/introduction)
* [Spring Security OAuth 2.0](https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html)
* [Microservices Security Patterns](https://microservices.io/patterns/security/microservice-security.html)

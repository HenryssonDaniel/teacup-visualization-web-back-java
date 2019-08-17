package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static org.assertj.core.api.Assertions.assertThat;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.github.henryssondaniel.teacup.core.configuration.Factory;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response.Status;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class AccountResourceTest {
  private static final String EMAIL = "email";
  private static final String EMAIL_VALUE = "admin@teacup.com";
  private static final String ID = "id";
  private static final String ID_VALUE = "123";
  private static final String INVALID_TOKEN = "The token is not valid";
  private static final String PASSWORD_JSON = "\"password\": \"password\"";
  private static final String SECRET = "secret";
  private static final String SECRET_KEY = "secret.key";

  private final HttpServletRequest httpServletRequest = new TestHttpServletRequest();

  @Test
  void authorized() {
    httpServletRequest.getSession().setAttribute(ID, ID_VALUE);
    verifyAuthorized(Status.OK.getStatusCode());
  }

  @Test
  void authorizedWhenUnauthorized() {
    verifyAuthorized(Status.UNAUTHORIZED.getStatusCode());
  }

  @Disabled("Needs visualization service and database connection")
  @Test
  void changePassword() {
    verifyChangePassword(Status.OK.getStatusCode());
  }

  @Test
  void changePasswordWhenAuthorized() {
    httpServletRequest.getSession().setAttribute(ID, ID_VALUE);
    verifyChangePassword(Status.UNAUTHORIZED.getStatusCode());
  }

  @Disabled("Needs visualization service and database connection")
  @Test
  void logIn() {
    verifyLogIn(Status.OK.getStatusCode());
    assertThat(httpServletRequest.getSession().getAttribute(ID)).isNotNull();
  }

  @Test
  void logInWhenAuthorized() {
    httpServletRequest.getSession().setAttribute(ID, ID_VALUE);
    verifyLogIn(Status.UNAUTHORIZED.getStatusCode());
  }

  @Test
  void logOut() {
    var httpSession = httpServletRequest.getSession();
    httpSession.setAttribute(ID, ID_VALUE);

    logOut(Status.OK.getStatusCode());
    assertThat(httpSession.getAttribute(ID)).isNull();
  }

  @Test
  void logOutWhenUnauthorized() {
    logOut(Status.UNAUTHORIZED.getStatusCode());
  }

  @Disabled(
      "Needs visualization service and database connection. Since the account can only be verified"
          + " once, the check that the token is valid instead of checking for an OK.")
  @Test
  void verify() {
    assertThat(
            new AccountResource()
                .verify(
                    JWT.create()
                        .withClaim(EMAIL, EMAIL_VALUE)
                        .sign(
                            Algorithm.HMAC256(
                                Factory.getProperties().getProperty(SECRET_KEY, SECRET)))))
        .isNotEqualTo(INVALID_TOKEN);
  }

  @Test
  void verifyWhenNotValid() {
    assertThat(new AccountResource().verify(ID_VALUE)).isEqualTo(INVALID_TOKEN);
  }

  private void logOut(int statusCode) {
    try (var response = AccountResource.logOut(httpServletRequest)) {
      assertThat(response.getEntity()).isNull();
      assertThat(response.getMediaType()).isNull();
      assertThat(response.getStatus()).isEqualTo(statusCode);
    }
  }

  private void verifyAuthorized(int statusCode) {
    try (var response = AccountResource.authorized(httpServletRequest)) {
      assertThat(response.getEntity()).isNull();
      assertThat(response.getMediaType()).isNull();
      assertThat(response.getStatus()).isEqualTo(statusCode);
    }
  }

  private void verifyChangePassword(int statusCode) {
    try (var response =
        new AccountResource()
            .changePassword(
                '{'
                    + String.join(
                        ", ",
                        PASSWORD_JSON,
                        "\"token\": \""
                            + JWT.create()
                                .withClaim(EMAIL, EMAIL_VALUE)
                                .withExpiresAt(Date.from(Instant.now().plus(1L, ChronoUnit.HOURS)))
                                .sign(
                                    Algorithm.HMAC256(
                                        Factory.getProperties().getProperty(SECRET_KEY, SECRET)))
                            + '"')
                    + '}',
                httpServletRequest)) {
      assertThat(response.getEntity()).isNull();
      assertThat(response.getMediaType()).isNull();
      assertThat(response.getStatus()).isEqualTo(statusCode);
    }
  }

  private void verifyLogIn(int statusCode) {
    try (var response =
        new AccountResource()
            .logIn(
                '{' + String.join(", ", "\"email\": \"admin@teacup.com\"", PASSWORD_JSON) + '}',
                httpServletRequest)) {
      assertThat(response.getEntity()).isNull();
      assertThat(response.getMediaType()).isNull();
      assertThat(response.getStatus()).isEqualTo(statusCode);
    }
  }
}

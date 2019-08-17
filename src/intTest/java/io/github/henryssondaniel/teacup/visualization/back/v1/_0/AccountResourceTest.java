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
  private static final String ID = "id";
  private static final String ID_VALUE = "123";

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
                "{\"password\": \"password\", \"token\": \""
                    + JWT.create()
                        .withClaim("email", "admin@teacup.com")
                        .withExpiresAt(Date.from(Instant.now().plus(1L, ChronoUnit.HOURS)))
                        .sign(Algorithm.HMAC256(Factory.getProperties().getProperty("secret.key")))
                    + "\"}",
                httpServletRequest)) {
      assertThat(response.getEntity()).isNull();
      assertThat(response.getMediaType()).isNull();
      assertThat(response.getStatus()).isEqualTo(statusCode);
    }
  }
}

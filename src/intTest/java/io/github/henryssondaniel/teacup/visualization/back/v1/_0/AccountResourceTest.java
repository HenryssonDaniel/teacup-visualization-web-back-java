package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static org.assertj.core.api.Assertions.assertThat;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response.Status;
import org.junit.jupiter.api.Test;

class AccountResourceTest {
  private final HttpServletRequest httpServletRequest = new TestHttpServletRequest();

  @Test
  void authorized() {
    httpServletRequest.getSession().setAttribute("id", "123");
    verifyAuthorized(Status.OK.getStatusCode());
  }

  @Test
  void authorizedWhenUnauthorized() {
    verifyAuthorized(Status.UNAUTHORIZED.getStatusCode());
  }

  @Test
  void logOut() {
    var httpSession = httpServletRequest.getSession();
    httpSession.setAttribute("id", "123");
    logOut(Status.OK.getStatusCode());
    assertThat(httpSession.getAttribute("id")).isNull();
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
}

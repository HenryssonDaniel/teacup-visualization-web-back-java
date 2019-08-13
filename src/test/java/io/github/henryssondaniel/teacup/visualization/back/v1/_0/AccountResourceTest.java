package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map.Entry;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.Response.StatusType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AccountResourceTest {
  private static final String ALLOW_CREDENTIALS = "Access-Control-Allow-credentials";
  private static final String ID = "id";
  private static final String ID_VALUE = "123";

  private final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
  private final HttpSession httpSession = mock(HttpSession.class);

  @Test
  void authorized() {
    authorize();
    authorized(Status.OK);

    verifyHttpServletRequest();
    verifyHttpSessionId();
  }

  @Test
  void authorizedWhenNotAuthorized() {
    authorized(Status.UNAUTHORIZED);

    verifyHttpServletRequest();
    verifyHttpSessionId();
  }

  @BeforeEach
  void beforeEach() {
    when(httpServletRequest.getSession()).thenReturn(httpSession);
  }

  @Test
  void logOut() {
    authorize();

    logOut(Status.OK);

    verifyHttpServletRequest();

    verify(httpSession).invalidate();
    verifyHttpSessionId();
  }

  @Test
  void logOutWhenNotAuthorized() {
    logOut(Status.UNAUTHORIZED);

    verifyHttpServletRequest();
    verifyHttpSessionId();
  }

  private void authorize() {
    when(httpSession.getAttribute(ID)).thenReturn(ID_VALUE);
  }

  private void authorized(StatusType statusType) {
    try (var response = AccountResource.authorized(httpServletRequest)) {
      verifyResponse(response, statusType);
    }
  }

  private void logOut(StatusType statusType) {
    try (var response = AccountResource.logOut(httpServletRequest)) {
      verifyResponse(response, statusType);
    }
  }

  private void verifyHttpServletRequest() {
    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);
  }

  private void verifyHttpSessionId() {
    verify(httpSession).getAttribute(ID);
    verifyNoMoreInteractions(httpSession);
  }

  private static void verifyResponse(Response response, StatusType statusType) {
    assertThat(response.getStatus()).isEqualTo(statusType.getStatusCode());

    Iterable<Entry<String, List<Object>>> entrySet = response.getHeaders().entrySet();
    assertThat(entrySet).hasSize(1);

    var entry = entrySet.iterator().next();

    assertThat(entry.getKey()).isEqualTo(ALLOW_CREDENTIALS);
    assertThat(entry.getValue()).containsExactly("true");
  }
}

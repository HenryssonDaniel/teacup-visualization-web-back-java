package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static java.lang.String.join;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.auth0.jwt.interfaces.JWTVerifier;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.Response.StatusType;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AccountResourceTest {
  private static final String ALLOW_CREDENTIALS = "Access-Control-Allow-credentials";
  private static final String ID = "id";
  private static final String ID_VALUE = "123";
  private static final String JSON_PASSWORD = "\"password\": \"password\"";
  private static final String JSON_TOKEN = "\"token\": \"123\"";

  private final Account account = mock(Account.class);
  private final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
  private final HttpSession httpSession = mock(HttpSession.class);
  private final Properties properties = mock(Properties.class);

  @Test
  void authorized() {
    authorize();
    authorized(Status.OK);

    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);

    verify(httpSession).getAttribute(ID);
    verifyNoMoreInteractions(httpSession);
  }

  @Test
  void authorizedWhenNotAuthorized() {
    authorized(Status.UNAUTHORIZED);

    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);

    verify(httpSession).getAttribute(ID);
    verifyNoMoreInteractions(httpSession);
  }

  @BeforeEach
  void beforeEach() {
    when(httpServletRequest.getSession()).thenReturn(httpSession);
    when(properties.getProperty("secret.key")).thenReturn("secret");
  }

  @Test
  void changePassword() {
    when(account.changePassword(same(httpSession), any(JSONObject.class), any(JWTVerifier.class)))
        .thenReturn(Response.ok());

    try (var response =
        new AccountResource(account, null, null, properties)
            .changePassword(
                '{' + join(", ", JSON_TOKEN, JSON_PASSWORD) + '}', httpServletRequest)) {
      verifyResponse(response, Status.OK);
    }

    verify(account)
        .changePassword(same(httpSession), any(JSONObject.class), any(JWTVerifier.class));

    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);

    verify(httpSession).getAttribute(ID);
    verifyNoMoreInteractions(httpSession);
  }

  @Test
  void changePasswordWhenAuthorized() {
    authorize();

    try (var response =
        new AccountResource()
            .changePassword(
                '{' + join(", ", JSON_TOKEN, JSON_PASSWORD) + '}', httpServletRequest)) {
      verifyResponse(response, Status.UNAUTHORIZED);
    }

    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);

    verify(httpSession).getAttribute(ID);
    verifyNoMoreInteractions(httpSession);
  }

  @Test
  void logOut() {
    authorize();

    logOut(Status.OK);

    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);

    verify(httpSession).getAttribute(ID);
    verify(httpSession).invalidate();
    verifyNoMoreInteractions(httpSession);
  }

  @Test
  void logOutWhenNotAuthorized() {
    logOut(Status.UNAUTHORIZED);

    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);

    verify(httpSession).getAttribute(ID);
    verifyNoMoreInteractions(httpSession);
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

  private static void verifyResponse(Response response, StatusType statusType) {
    assertThat(response.getStatus()).isEqualTo(statusType.getStatusCode());

    Iterable<Entry<String, List<Object>>> entrySet = response.getHeaders().entrySet();
    assertThat(entrySet).hasSize(1);

    var entry = entrySet.iterator().next();

    assertThat(entry.getKey()).isEqualTo(ALLOW_CREDENTIALS);
    assertThat(entry.getValue()).containsExactly("true");
  }
}

package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.Response.StatusType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class AccountResourceTest {
  private static final String ALLOW_CREDENTIALS = "Access-Control-Allow-credentials";
  private static final String TRUE = "true";

  private final HttpClient httpClient = mock(HttpClient.class);
  private final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
  private final HttpSession httpSession = mock(HttpSession.class);
  private final JWTVerifier jwtVerifier = mock(JWTVerifier.class);
  private final Properties properties = mock(Properties.class);
  @Mock private HttpResponse<String> httpResponse;

  @Test
  void authorized() {
    when(httpSession.getAttribute("id")).thenReturn("123");

    try (var response = AccountResource.authorized(httpServletRequest)) {
      verifyResponse(response, Status.OK);
    }

    verifyMocks();
  }

  @Test
  void authorizedWhenNotAuthorized() {
    try (var response = AccountResource.authorized(httpServletRequest)) {
      verifyResponse(response, Status.UNAUTHORIZED);
    }

    verifyMocks();
  }

  @BeforeEach
  void beforeEach() {
    MockitoAnnotations.initMocks(this);

    when(httpServletRequest.getSession()).thenReturn(httpSession);
    when(properties.getProperty("service.visualization")).thenReturn("http://localhost");
  }

  @Test
  void changePassword() throws IOException, InterruptedException {
    var claim = mock(Claim.class);
    when(claim.asString()).thenReturn("email");

    var decodedJWT = mock(DecodedJWT.class);
    when(decodedJWT.getClaim("email")).thenReturn(claim);

    when(jwtVerifier.verify("123")).thenReturn(decodedJWT);

    when(httpResponse.statusCode()).thenReturn(Status.FOUND.getStatusCode());

    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenReturn(httpResponse);

    try (var response =
        new AccountResource(httpClient, jwtVerifier, properties)
            .changePassword(
                "{\"token\": \"123\", \"password\": \"password\"}", httpServletRequest)) {
      verifyResponse(response, Status.FOUND);
    }

    verifyMocks();
    verify(jwtVerifier).verify("123");
    verifyNoMoreInteractions(jwtVerifier);
  }

  @Test
  void changePasswordWhenAuthorized() {
    when(httpSession.getAttribute("id")).thenReturn("123");

    try (var response = new AccountResource().changePassword("{}", httpServletRequest)) {
      verifyResponse(response, Status.UNAUTHORIZED);
    }

    verifyMocks();
  }

  @Test
  void changePasswordWhenInvalidToken() {
    when(jwtVerifier.verify("123")).thenThrow(new JWTVerificationException("test"));

    try (var response =
        new AccountResource(httpClient, jwtVerifier, properties)
            .changePassword("{\"token\": \"123\"}", httpServletRequest)) {
      verifyResponse(response, Status.FORBIDDEN);
    }

    verifyMocks();
    verify(jwtVerifier).verify("123");
    verifyNoMoreInteractions(jwtVerifier);
  }

  private static void verifyKeyValue(
      Iterator<? extends Entry<String, List<Object>>> iterator, String key, Object value) {
    var entry = iterator.next();

    assertThat(entry.getKey()).isEqualTo(key);
    assertThat(entry.getValue()).containsExactly(value);
  }

  private void verifyMocks() {
    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);

    verify(httpSession).getAttribute("id");
    verifyNoMoreInteractions(httpSession);
  }

  private static void verifyResponse(Response response, StatusType statusType) {
    assertThat(response.getStatus()).isEqualTo(statusType.getStatusCode());

    Iterable<Entry<String, List<Object>>> entrySet = response.getHeaders().entrySet();
    assertThat(entrySet).hasSize(1);
    verifyKeyValue(entrySet.iterator(), ALLOW_CREDENTIALS, TRUE);
  }
}

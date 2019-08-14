package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static java.lang.String.join;
import static javax.ws.rs.core.Response.Status.OK;
import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.StatusType;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AccountResourceTest {
  private static final String ALLOW_CREDENTIALS = "Access-Control-Allow-credentials";
  private static final String EMAIL = "email";
  private static final String ID = "id";
  private static final String ID_VALUE = "123";
  private static final String JSON_EMAIL = "\"email\": \"email\"";
  private static final String JSON_EMPTY = "{}";
  private static final String JSON_PASSWORD = "\"password\": \"password\"";
  private static final String SECRET = "password";
  private static final String SECRET_KEY = "secret.key";
  private static final String SUCCESS = "success";
  private static final String TOKEN = "token";

  private final Account account = mock(Account.class);
  private final Algorithm algorithm = mock(Algorithm.class);
  private final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
  private final HttpSession httpSession = mock(HttpSession.class);
  private final JWTVerifier jwtVerifier = mock(JWTVerifier.class);
  private final Properties properties = mock(Properties.class);

  @Test
  void authorized() {
    authorize();
    authorized(OK);

    verifyHttp();
  }

  @Test
  void authorizedWhenNotAuthorized() {
    authorized(UNAUTHORIZED);
    verifyHttp();
  }

  @BeforeEach
  void beforeEach() {
    when(httpServletRequest.getSession()).thenReturn(httpSession);
    when(properties.getProperty(SECRET_KEY)).thenReturn("secret");
  }

  @Test
  void changePassword() {
    when(account.changePassword(same(httpSession), any(JSONObject.class), any(JWTVerifier.class)))
        .thenReturn(Response.ok());

    try (var response =
        new AccountResource(account, null, null, properties)
            .changePassword(JSON_EMPTY, httpServletRequest)) {
      verifyResponse(response, OK);
    }

    verify(account)
        .changePassword(same(httpSession), any(JSONObject.class), any(JWTVerifier.class));
    verifyNoMoreInteractions(account);

    verifyHttp();

    verify(properties).getProperty(SECRET_KEY);
  }

  @Test
  void changePasswordWhenAuthorized() {
    authorize();

    try (var response = new AccountResource().changePassword(JSON_EMPTY, httpServletRequest)) {
      verifyResponse(response, UNAUTHORIZED);
    }

    verifyHttp();
  }

  @Test
  void logIn() {
    when(account.logIn(EMAIL, httpSession, SECRET)).thenReturn(OK.getStatusCode());

    logIn(OK);

    verify(account).logIn(EMAIL, httpSession, SECRET);
    verifyNoMoreInteractions(account);

    verifyHttp();
  }

  @Test
  void logInWhenAuthorized() {
    authorize();

    logIn(UNAUTHORIZED);

    verifyZeroInteractions(account);
    verifyHttp();
  }

  @Test
  void logOut() {
    authorize();

    logOut(OK);

    verify(httpSession).invalidate();
    verifyHttp();
  }

  @Test
  void logOutWhenNotAuthorized() {
    logOut(UNAUTHORIZED);
    verifyHttp();
  }

  @Test
  void recover() {
    when(account.recover(algorithm, EMAIL)).thenReturn(OK.getStatusCode());

    recover(OK);

    verify(account).recover(algorithm, EMAIL);
    verifyNoMoreInteractions(account);

    verifyZeroInteractions(algorithm);
    verifyHttp();
  }

  @Test
  void recoverWhenAuthorized() {
    authorize();

    recover(UNAUTHORIZED);

    verifyZeroInteractions(account);
    verifyZeroInteractions(algorithm);
    verifyHttp();
  }

  @Test
  void signUp() {
    when(account.signUp(same(algorithm), same(httpServletRequest), any(JSONObject.class)))
        .thenReturn(OK.getStatusCode());

    signUp(OK);

    verify(account).signUp(same(algorithm), same(httpServletRequest), any(JSONObject.class));
    verifyNoMoreInteractions(account);

    verifyZeroInteractions(algorithm);
    verifyHttp();
  }

  @Test
  void signUpWhenAuthorized() {
    authorize();

    signUp(UNAUTHORIZED);

    verifyZeroInteractions(account);
    verifyZeroInteractions(algorithm);
    verifyHttp();
  }

  @Test
  void verifyAccount() {
    when(account.verify(EMAIL)).thenReturn(SUCCESS);

    var claim = mock(Claim.class);
    when(claim.asString()).thenReturn(EMAIL);

    var decodedJWT = mock(DecodedJWT.class);
    when(decodedJWT.getClaim(EMAIL)).thenReturn(claim);

    when(jwtVerifier.verify(TOKEN)).thenReturn(decodedJWT);

    verifyVerify(SUCCESS);

    verify(account).verify(EMAIL);
    verifyNoMoreInteractions(account);

    verifyZeroInteractions(algorithm);

    verify(claim).asString();
    verifyNoMoreInteractions(claim);

    verify(decodedJWT).getClaim(EMAIL);
    verifyNoMoreInteractions(decodedJWT);

    verify(jwtVerifier).verify(TOKEN);
    verifyNoMoreInteractions(jwtVerifier);
  }

  @Test
  void verifyWhenInvalidToken() {
    when(jwtVerifier.verify(TOKEN)).thenThrow(new JWTVerificationException("test"));

    verifyVerify("The token is not valid");

    verifyZeroInteractions(account);
    verifyZeroInteractions(algorithm);

    verify(jwtVerifier).verify(TOKEN);
    verifyNoMoreInteractions(jwtVerifier);
  }

  private void authorize() {
    when(httpSession.getAttribute(ID)).thenReturn(ID_VALUE);
  }

  private void authorized(StatusType statusType) {
    try (var response = AccountResource.authorized(httpServletRequest)) {
      verifyResponse(response, statusType);
    }
  }

  private void logIn(StatusType statusType) {
    try (var response =
        new AccountResource(account, null, null, null)
            .logIn('{' + join(", ", JSON_EMAIL, JSON_PASSWORD) + '}', httpServletRequest)) {
      verifyResponse(response, statusType);
    }
  }

  private void logOut(StatusType statusType) {
    try (var response = AccountResource.logOut(httpServletRequest)) {
      verifyResponse(response, statusType);
    }
  }

  private void recover(StatusType statusType) {
    try (var response =
        new AccountResource(account, algorithm, null, null)
            .recover('{' + JSON_EMAIL + '}', httpServletRequest)) {
      verifyResponse(response, statusType);
    }
  }

  private void signUp(StatusType statusType) {
    try (var response =
        new AccountResource(account, algorithm, null, null)
            .signUp(JSON_EMPTY, httpServletRequest)) {
      verifyResponse(response, statusType);
    }
  }

  private void verifyHttp() {
    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);

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

  private void verifyVerify(String message) {
    assertThat(new AccountResource(account, algorithm, jwtVerifier, null).verify(TOKEN))
        .isEqualTo(message);
  }
}

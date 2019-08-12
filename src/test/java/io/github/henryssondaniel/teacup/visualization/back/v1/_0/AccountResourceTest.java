package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static java.lang.String.join;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.sun.mail.smtp.SMTPTransport;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;
import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Transport;
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
  private static final String EMAIL = "email";
  private static final String FIRST_NAME = "firstName";
  private static final String ID = "id";
  private static final String ID_VALUE = "123";
  private static final String JSON_EMAIL = "\"email\": \"email\"";
  private static final String JSON_FIRST_NAME = "\"firstName\": \"firstName\"";
  private static final String JSON_ID = "\"id\": \"123\"";
  private static final String JSON_LAST_NAME = "\"lastName\": \"lastName\"";
  private static final String JSON_PASSWORD = "\"password\": \"password\"";
  private static final String JSON_TOKEN = "\"token\": \"123\"";
  private static final String LAST_NAME = "lastName";
  private static final String SERVICE = "service.visualization";
  private static final String TEST = "test";
  private static final InterruptedException INTERRUPTED_EXCEPTION = new InterruptedException(TEST);
  private static final IOException IO_EXCEPTION = new IOException(TEST);

  private final Algorithm algorithm = mock(Algorithm.class);
  private final Claim claim = mock(Claim.class);
  private final DecodedJWT decodedJWT = mock(DecodedJWT.class);
  private final HttpClient httpClient = mock(HttpClient.class);
  private final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
  private final HttpSession httpSession = mock(HttpSession.class);
  private final JWTVerifier jwtVerifier = mock(JWTVerifier.class);
  private final Properties properties = mock(Properties.class);
  private final Transport transport = mock(SMTPTransport.class);
  @Mock private HttpResponse<String> httpResponse;

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
  void beforeEach() throws IOException, InterruptedException {
    MockitoAnnotations.initMocks(this);

    when(claim.asString()).thenReturn(EMAIL);
    when(decodedJWT.getClaim(EMAIL)).thenReturn(claim);
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenReturn(httpResponse);
    when(httpResponse.body())
        .thenReturn('{' + join(", ", JSON_EMAIL, JSON_FIRST_NAME, JSON_ID, JSON_LAST_NAME) + '}');
    when(httpResponse.statusCode()).thenReturn(Status.OK.getStatusCode());
    when(httpServletRequest.getSession()).thenReturn(httpSession);
    when(jwtVerifier.verify(ID_VALUE)).thenReturn(decodedJWT);
    when(properties.getProperty(SERVICE)).thenReturn("http://localhost");
    when(properties.getProperty("smtp.from")).thenReturn("localhost");
    when(properties.getProperty("smtp.host")).thenReturn("localhost");
    when(properties.getProperty("smtp.port")).thenReturn("8080");
  }

  @Test
  void changePassword() throws IOException, InterruptedException {
    changePassword(Status.OK);

    verifyChangePassword(2);

    verify(httpResponse).body();
    verify(httpResponse, times(2)).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyHttpSessionLogIn();
  }

  @Test
  void changePasswordWhenAuthorized() {
    authorize();

    changePassword(Status.UNAUTHORIZED);

    verifyValidationError();
    verifyZeroInteractions(jwtVerifier);
  }

  @Test
  void changePasswordWhenInterruptedException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(INTERRUPTED_EXCEPTION);
    when(httpResponse.statusCode()).thenReturn(Status.FOUND.getStatusCode());

    changePassword(Status.INTERNAL_SERVER_ERROR);

    verifyChangePassword(1);
    verifyZeroInteractions(httpResponse);
    verifyHttpSessionId();
  }

  @Test
  void changePasswordWhenInvalidToken() {
    when(jwtVerifier.verify(ID_VALUE)).thenThrow(new JWTVerificationException(TEST));

    changePassword(Status.FORBIDDEN);

    verifyValidationError();

    verify(jwtVerifier).verify(ID_VALUE);
    verifyNoMoreInteractions(jwtVerifier);
  }

  @Test
  void changePasswordWhenIoException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(IO_EXCEPTION);
    when(httpResponse.statusCode()).thenReturn(Status.FOUND.getStatusCode());

    changePassword(Status.INTERNAL_SERVER_ERROR);

    verifyChangePassword(1);
    verifyZeroInteractions(httpResponse);
    verifyHttpSessionId();
  }

  @Test
  void changePasswordWhenLogInInterruptedException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenReturn(httpResponse)
        .thenThrow(INTERRUPTED_EXCEPTION);

    changePassword(Status.INTERNAL_SERVER_ERROR);

    verifyChangePassword(2);

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyHttpSessionId();
  }

  @Test
  void changePasswordWhenLogInIoException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenReturn(httpResponse)
        .thenThrow(IO_EXCEPTION);

    changePassword(Status.INTERNAL_SERVER_ERROR);

    verifyChangePassword(2);

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyHttpSessionId();
  }

  @Test
  void changePasswordWhenLogInNotOk() throws IOException, InterruptedException {
    when(httpResponse.statusCode())
        .thenReturn(Status.OK.getStatusCode(), Status.FOUND.getStatusCode());

    changePassword(Status.FOUND);

    verifyChangePassword(2);

    verify(httpResponse, times(2)).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyHttpSessionId();
  }

  @Test
  void changePasswordWhenNotOk() throws IOException, InterruptedException {
    when(httpResponse.statusCode()).thenReturn(Status.FOUND.getStatusCode());

    changePassword(Status.FOUND);

    verifyChangePassword(1);

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyHttpSessionId();
  }

  @Test
  void logIn() throws IOException, InterruptedException {
    logIn(Status.OK);

    verifyLogIn();

    verify(httpResponse).body();
    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyHttpSessionLogIn();
  }

  @Test
  void logInWhenAuthorized() {
    authorize();

    try (var response =
        new AccountResource()
            .logIn('{' + join(", ", JSON_EMAIL, JSON_PASSWORD) + '}', httpServletRequest)) {
      verifyResponse(response, Status.UNAUTHORIZED);
    }

    verifyValidationError();
    verifyZeroInteractions(httpResponse);
    verifyZeroInteractions(jwtVerifier);
  }

  @Test
  void logInWhenInterruptedException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(INTERRUPTED_EXCEPTION);

    logIn(Status.INTERNAL_SERVER_ERROR);

    verifyLogIn();
    verifyZeroInteractions(httpResponse);
    verifyHttpSessionId();
  }

  @Test
  void logInWhenIoException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(IO_EXCEPTION);

    logIn(Status.INTERNAL_SERVER_ERROR);

    verifyLogIn();
    verifyZeroInteractions(httpResponse);
    verifyHttpSessionId();
  }

  @Test
  void logInWhenNotOk() throws IOException, InterruptedException {
    when(httpResponse.statusCode()).thenReturn(Status.FOUND.getStatusCode());

    logIn(Status.FOUND);

    verifyLogIn();

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyHttpSessionId();
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

  @Test
  void recover() throws IOException, InterruptedException, MessagingException {
    recover(Status.OK);

    verify(algorithm).getName();
    verify(algorithm).getSigningKeyId();
    verify(algorithm).sign(any(byte[].class), any(byte[].class));
    verifyNoMoreInteractions(algorithm);

    verifyZeroInteractions(claim);
    verifyZeroInteractions(decodedJWT);

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verifyHttpServletRequest();

    verifyZeroInteractions(jwtVerifier);

    verify(properties).getProperty(SERVICE);
    verify(properties).getProperty("smtp.from");
    verify(properties).getProperty("smtp.host");
    verify(properties).getProperty("smtp.port");
    verifyNoMoreInteractions(properties);

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyHttpSessionId();

    verify(transport).close();
    verify(transport).connect();
    verify(transport).sendMessage(any(Message.class), any(Address[].class));
    verifyNoMoreInteractions(transport);
  }

  @Test
  void recoverWhenAuthorized() {
    authorize();

    recover(Status.UNAUTHORIZED);

    verifyValidationError();
    verifyZeroInteractions(httpResponse);
    verifyZeroInteractions(jwtVerifier);
  }

  @Test
  void recoverWhenInterruptedException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(INTERRUPTED_EXCEPTION);

    recover(Status.INTERNAL_SERVER_ERROR);

    verifyRecover();
    verifyZeroInteractions(httpResponse);
    verifyHttpSessionId();
  }

  @Test
  void recoverWhenIoException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(IO_EXCEPTION);

    recover(Status.INTERNAL_SERVER_ERROR);

    verifyRecover();
    verifyZeroInteractions(httpResponse);
    verifyHttpSessionId();
  }

  @Test
  void recoverWhenNotOk() throws IOException, InterruptedException {
    when(httpResponse.statusCode()).thenReturn(Status.FOUND.getStatusCode());

    recover(Status.FOUND);

    verifyRecover();

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

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

  private void changePassword(StatusType statusType) {
    try (var response =
        new AccountResource(algorithm, httpClient, jwtVerifier, properties, transport)
            .changePassword(
                '{' + join(", ", JSON_TOKEN, JSON_PASSWORD) + '}', httpServletRequest)) {
      verifyResponse(response, statusType);
    }
  }

  private void logIn(StatusType statusType) {
    try (var response =
        new AccountResource(algorithm, httpClient, jwtVerifier, properties, transport)
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
        new AccountResource(algorithm, httpClient, jwtVerifier, properties, transport)
            .recover('{' + join(", ", JSON_EMAIL) + '}', httpServletRequest)) {
      verifyResponse(response, statusType);
    }
  }

  private void verifyChangePassword(int times) throws IOException, InterruptedException {
    verifyZeroInteractions(algorithm);

    verify(claim).asString();
    verifyNoMoreInteractions(claim);

    verify(decodedJWT).getClaim(EMAIL);
    verifyNoMoreInteractions(decodedJWT);

    verify(httpClient, times(times)).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verifyHttpServletRequest();

    verify(jwtVerifier).verify(ID_VALUE);
    verifyNoMoreInteractions(jwtVerifier);

    verify(properties, times(times)).getProperty(SERVICE);
    verifyNoMoreInteractions(properties);

    verifyZeroInteractions(transport);
  }

  private void verifyHttpServletRequest() {
    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);
  }

  private void verifyHttpSessionId() {
    verify(httpSession).getAttribute(ID);
    verifyNoMoreInteractions(httpSession);
  }

  private void verifyHttpSessionLogIn() {
    verify(httpSession).getAttribute(ID);
    verify(httpSession).setAttribute(EMAIL, EMAIL);
    verify(httpSession).setAttribute(FIRST_NAME, FIRST_NAME);
    verify(httpSession).setAttribute(ID, ID_VALUE);
    verify(httpSession).setAttribute(LAST_NAME, LAST_NAME);
    verifyNoMoreInteractions(httpSession);
  }

  private void verifyLogIn() throws IOException, InterruptedException {
    verifyZeroInteractions(algorithm);

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verifyHttpServletRequest();

    verify(properties).getProperty(SERVICE);
    verifyNoMoreInteractions(properties);

    verifyZeroInteractions(transport);
  }

  private void verifyRecover() throws IOException, InterruptedException {
    verifyZeroInteractions(algorithm);
    verifyZeroInteractions(claim);
    verifyZeroInteractions(decodedJWT);

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verifyHttpServletRequest();

    verifyZeroInteractions(jwtVerifier);

    verify(properties).getProperty(SERVICE);
    verifyNoMoreInteractions(properties);

    verifyZeroInteractions(transport);
  }

  private static void verifyResponse(Response response, StatusType statusType) {
    assertThat(response.getStatus()).isEqualTo(statusType.getStatusCode());

    Iterable<Entry<String, List<Object>>> entrySet = response.getHeaders().entrySet();
    assertThat(entrySet).hasSize(1);

    var entry = entrySet.iterator().next();

    assertThat(entry.getKey()).isEqualTo(ALLOW_CREDENTIALS);
    assertThat(entry.getValue()).containsExactly("true");
  }

  private void verifyValidationError() {
    verifyZeroInteractions(algorithm);
    verifyZeroInteractions(claim);
    verifyZeroInteractions(decodedJWT);
    verifyZeroInteractions(httpClient);
    verifyZeroInteractions(httpResponse);

    verifyHttpServletRequest();
    verifyHttpSessionId();

    verifyZeroInteractions(properties);
    verifyZeroInteractions(transport);
  }
}

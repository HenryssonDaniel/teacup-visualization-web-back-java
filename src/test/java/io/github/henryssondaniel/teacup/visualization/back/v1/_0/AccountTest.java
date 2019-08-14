package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static javax.ws.rs.core.Response.Status.FORBIDDEN;
import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;
import static javax.ws.rs.core.Response.Status.NO_CONTENT;
import static javax.ws.rs.core.Response.Status.OK;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.doThrow;
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
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Properties;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Transport;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class AccountTest {

  private static final String EMAIL = "email";
  private static final String FIRST_NAME = "firstName";
  private static final String JSON_EMAIL = "\"email\": \"email\"";
  private static final String JSON_FIRST_NAME = "\"firstName\": \"firstName\"";
  private static final String JSON_ID = "\"id\": \"123\"";
  private static final String JSON_LAST_NAME = "\"lastName\": \"lastName\"";
  private static final String LAST_NAME = "lastName";
  private static final String RECOVER = "Recover";
  private static final String RECOVER_CODE = "The recover code: ";
  private static final String SECRET = "password";
  private static final String SMTP_HOST = "smtp.host";
  private static final String SMTP_PORT = "smtp.port";
  private static final String TOKEN = "token";
  private static final String VISUALIZATION = "service.visualization";

  private final Algorithm algorithm = mock(Algorithm.class);
  private final Claim claim = mock(Claim.class);
  private final DecodedJWT decodedJWT = mock(DecodedJWT.class);
  private final EmailClient emailClient = mock(EmailClient.class);
  private final HttpClient httpClient = mock(HttpClient.class);
  private final HttpSession httpSession = mock(HttpSession.class);
  private final JSONObject jsonObject = mock(JSONObject.class);
  private final JWTVerifier jwtVerifier = mock(JWTVerifier.class);
  private final Properties properties = mock(Properties.class);

  @Mock private HttpResponse<String> httpResponse;

  @BeforeEach
  void beforeEach() throws IOException, InterruptedException {
    MockitoAnnotations.initMocks(this);

    when(claim.asString()).thenReturn(EMAIL);
    when(decodedJWT.getClaim(EMAIL)).thenReturn(claim);
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenReturn(httpResponse);
    when(httpResponse.body())
        .thenReturn(
            '{' + String.join(", ", JSON_EMAIL, JSON_FIRST_NAME, JSON_ID, JSON_LAST_NAME) + '}');
    when(httpResponse.statusCode()).thenReturn(OK.getStatusCode());
    when(jsonObject.getString(TOKEN)).thenReturn(TOKEN);
    when(jwtVerifier.verify(TOKEN)).thenReturn(decodedJWT);
    when(properties.getProperty(VISUALIZATION)).thenReturn("http://localhost");
    when(properties.getProperty(SMTP_HOST)).thenReturn("localhost");
    when(properties.getProperty(SMTP_PORT)).thenReturn("8080");
  }

  @Test
  void changePassword() throws IOException, InterruptedException {
    assertThat(
            new AccountImpl(null, httpClient, properties)
                .changePassword(httpSession, jsonObject, jwtVerifier))
        .isEqualToComparingFieldByFieldRecursively(Response.status(OK));

    verify(claim).asString();
    verifyNoMoreInteractions(claim);

    verify(decodedJWT).getClaim(EMAIL);
    verifyNoMoreInteractions(decodedJWT);

    verify(httpClient, times(2)).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(httpResponse).body();
    verify(httpResponse, times(2)).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verify(httpSession).setAttribute(EMAIL, EMAIL);
    verify(httpSession).setAttribute(FIRST_NAME, FIRST_NAME);
    verify(httpSession).setAttribute("id", "123");
    verify(httpSession).setAttribute(LAST_NAME, LAST_NAME);
    verifyNoMoreInteractions(httpSession);

    verify(jsonObject).getString(SECRET);
    verify(jsonObject).getString(TOKEN);
    verifyNoMoreInteractions(jsonObject);

    verify(jwtVerifier).verify(TOKEN);
    verifyNoMoreInteractions(jwtVerifier);

    verify(properties, times(2)).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void changePasswordWhenInterruptedException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(new InterruptedException("test"));

    assertThat(
            new AccountImpl(null, httpClient, properties)
                .changePassword(httpSession, jsonObject, jwtVerifier))
        .isEqualToComparingFieldByFieldRecursively(Response.status(INTERNAL_SERVER_ERROR));

    verify(claim).asString();
    verifyNoMoreInteractions(claim);

    verify(decodedJWT).getClaim(EMAIL);
    verifyNoMoreInteractions(decodedJWT);

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verifyZeroInteractions(httpResponse);
    verifyZeroInteractions(httpSession);

    verify(jsonObject).getString(SECRET);
    verify(jsonObject).getString(TOKEN);
    verifyNoMoreInteractions(jsonObject);

    verify(jwtVerifier).verify(TOKEN);
    verifyNoMoreInteractions(jwtVerifier);

    verify(properties).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void changePasswordWhenInvalidToken() {
    when(jwtVerifier.verify(TOKEN)).thenThrow(new JWTVerificationException("test"));

    assertThat(
            new AccountImpl(httpClient, properties)
                .changePassword(httpSession, jsonObject, jwtVerifier))
        .isEqualToComparingFieldByFieldRecursively(Response.status(FORBIDDEN));

    verifyZeroInteractions(claim);
    verifyZeroInteractions(decodedJWT);
    verifyZeroInteractions(httpClient);
    verifyZeroInteractions(httpResponse);
    verifyZeroInteractions(httpSession);

    verify(jsonObject).getString(TOKEN);
    verifyNoMoreInteractions(jsonObject);

    verify(jwtVerifier).verify(TOKEN);
    verifyNoMoreInteractions(jwtVerifier);

    verifyZeroInteractions(properties);
  }

  @Test
  void changePasswordWhenIoException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(new IOException("test"));

    assertThat(
            new AccountImpl(null, httpClient, properties)
                .changePassword(httpSession, jsonObject, jwtVerifier))
        .isEqualToComparingFieldByFieldRecursively(Response.status(INTERNAL_SERVER_ERROR));

    verify(claim).asString();
    verifyNoMoreInteractions(claim);

    verify(decodedJWT).getClaim(EMAIL);
    verifyNoMoreInteractions(decodedJWT);

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verifyZeroInteractions(httpResponse);
    verifyZeroInteractions(httpSession);

    verify(jsonObject).getString(SECRET);
    verify(jsonObject).getString(TOKEN);
    verifyNoMoreInteractions(jsonObject);

    verify(jwtVerifier).verify(TOKEN);
    verifyNoMoreInteractions(jwtVerifier);

    verify(properties).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void changePasswordWhenLogInInterruptedException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenReturn(httpResponse)
        .thenThrow(new InterruptedException("test"));

    assertThat(
            new AccountImpl(null, httpClient, properties)
                .changePassword(httpSession, jsonObject, jwtVerifier))
        .isEqualToComparingFieldByFieldRecursively(Response.status(INTERNAL_SERVER_ERROR));

    verify(claim).asString();
    verifyNoMoreInteractions(claim);

    verify(decodedJWT).getClaim(EMAIL);
    verifyNoMoreInteractions(decodedJWT);

    verify(httpClient, times(2)).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyZeroInteractions(httpSession);

    verify(jsonObject).getString(SECRET);
    verify(jsonObject).getString(TOKEN);
    verifyNoMoreInteractions(jsonObject);

    verify(jwtVerifier).verify(TOKEN);
    verifyNoMoreInteractions(jwtVerifier);

    verify(properties, times(2)).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void changePasswordWhenLogInIoException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenReturn(httpResponse)
        .thenThrow(new IOException("test"));

    assertThat(
            new AccountImpl(null, httpClient, properties)
                .changePassword(httpSession, jsonObject, jwtVerifier))
        .isEqualToComparingFieldByFieldRecursively(Response.status(INTERNAL_SERVER_ERROR));

    verify(claim).asString();
    verifyNoMoreInteractions(claim);

    verify(decodedJWT).getClaim(EMAIL);
    verifyNoMoreInteractions(decodedJWT);

    verify(httpClient, times(2)).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyZeroInteractions(httpSession);

    verify(jsonObject).getString(SECRET);
    verify(jsonObject).getString(TOKEN);
    verifyNoMoreInteractions(jsonObject);

    verify(jwtVerifier).verify(TOKEN);
    verifyNoMoreInteractions(jwtVerifier);

    verify(properties, times(2)).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void changePasswordWhenLogInNotOk() throws IOException, InterruptedException {
    when(httpResponse.statusCode()).thenReturn(OK.getStatusCode(), NO_CONTENT.getStatusCode());

    assertThat(
            new AccountImpl(null, httpClient, properties)
                .changePassword(httpSession, jsonObject, jwtVerifier))
        .isEqualToComparingFieldByFieldRecursively(Response.status(NO_CONTENT));

    verify(claim).asString();
    verifyNoMoreInteractions(claim);

    verify(decodedJWT).getClaim(EMAIL);
    verifyNoMoreInteractions(decodedJWT);

    verify(httpClient, times(2)).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(httpResponse, times(2)).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyZeroInteractions(httpSession);

    verify(jsonObject).getString(SECRET);
    verify(jsonObject).getString(TOKEN);
    verifyNoMoreInteractions(jsonObject);

    verify(jwtVerifier).verify(TOKEN);
    verifyNoMoreInteractions(jwtVerifier);

    verify(properties, times(2)).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void changePasswordWhenNotOk() throws IOException, InterruptedException {
    when(httpResponse.statusCode()).thenReturn(NO_CONTENT.getStatusCode());

    assertThat(
            new AccountImpl(null, httpClient, properties)
                .changePassword(httpSession, jsonObject, jwtVerifier))
        .isEqualToComparingFieldByFieldRecursively(Response.status(NO_CONTENT));

    verify(claim).asString();
    verifyNoMoreInteractions(claim);

    verify(decodedJWT).getClaim(EMAIL);
    verifyNoMoreInteractions(decodedJWT);

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyZeroInteractions(httpSession);

    verify(jsonObject).getString(SECRET);
    verify(jsonObject).getString(TOKEN);
    verifyNoMoreInteractions(jsonObject);

    verify(jwtVerifier).verify(TOKEN);
    verifyNoMoreInteractions(jwtVerifier);

    verify(properties).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void logIn() throws IOException, InterruptedException {
    assertThat(new AccountImpl(null, httpClient, properties).logIn(EMAIL, httpSession, SECRET))
        .isEqualTo(OK.getStatusCode());

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(httpResponse).body();
    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verify(httpSession).setAttribute(EMAIL, EMAIL);
    verify(httpSession).setAttribute(FIRST_NAME, FIRST_NAME);
    verify(httpSession).setAttribute("id", "123");
    verify(httpSession).setAttribute(LAST_NAME, LAST_NAME);
    verifyNoMoreInteractions(httpSession);

    verify(properties).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void logInWhenInterruptedException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(new InterruptedException("test"));

    assertThat(new AccountImpl(null, httpClient, properties).logIn(EMAIL, httpSession, SECRET))
        .isEqualTo(INTERNAL_SERVER_ERROR.getStatusCode());

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verifyZeroInteractions(httpResponse);
    verifyZeroInteractions(httpSession);

    verify(properties).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void logInWhenIoException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(new IOException("test"));

    assertThat(new AccountImpl(null, httpClient, properties).logIn(EMAIL, httpSession, SECRET))
        .isEqualTo(INTERNAL_SERVER_ERROR.getStatusCode());

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verifyZeroInteractions(httpResponse);
    verifyZeroInteractions(httpSession);

    verify(properties).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void logInWhenNotOk() throws IOException, InterruptedException {
    when(httpResponse.statusCode()).thenReturn(NO_CONTENT.getStatusCode());

    assertThat(new AccountImpl(null, httpClient, properties).logIn(EMAIL, httpSession, SECRET))
        .isEqualTo(NO_CONTENT.getStatusCode());

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyZeroInteractions(httpSession);

    verify(properties).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void recover() throws IOException, InterruptedException, MessagingException {
    assertThat(new AccountImpl(emailClient, httpClient, properties).recover(algorithm, EMAIL))
        .isEqualTo(OK.getStatusCode());

    verify(algorithm).getName();
    verify(algorithm).getSigningKeyId();
    verify(algorithm).sign(any(byte[].class), any(byte[].class));
    verifyNoMoreInteractions(algorithm);

    verify(emailClient)
        .send(
            startsWith(RECOVER_CODE),
            any(Message.class),
            eq(RECOVER),
            eq(EMAIL),
            any(Transport.class));
    verifyNoMoreInteractions(emailClient);

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyZeroInteractions(httpSession);

    verify(properties).getProperty(VISUALIZATION);
    verify(properties).getProperty(SMTP_HOST);
    verify(properties).getProperty(SMTP_PORT);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void recoverWhenEmailError() throws IOException, InterruptedException, MessagingException {
    doThrow(new MessagingException("test"))
        .when(emailClient)
        .send(
            startsWith(RECOVER_CODE),
            any(Message.class),
            eq(RECOVER),
            eq(EMAIL),
            any(Transport.class));

    assertThat(new AccountImpl(emailClient, httpClient, properties).recover(algorithm, EMAIL))
        .isEqualTo(OK.getStatusCode());

    verify(algorithm).getName();
    verify(algorithm).getSigningKeyId();
    verify(algorithm).sign(any(byte[].class), any(byte[].class));
    verifyNoMoreInteractions(algorithm);

    verify(emailClient)
        .send(
            startsWith(RECOVER_CODE),
            any(Message.class),
            eq(RECOVER),
            eq(EMAIL),
            any(Transport.class));
    verifyNoMoreInteractions(emailClient);

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyZeroInteractions(httpSession);

    verify(properties).getProperty(VISUALIZATION);
    verify(properties).getProperty(SMTP_HOST);
    verify(properties).getProperty(SMTP_PORT);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void recoverWhenInterruptedException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(new InterruptedException("test"));

    assertThat(new AccountImpl(emailClient, httpClient, properties).recover(algorithm, EMAIL))
        .isEqualTo(INTERNAL_SERVER_ERROR.getStatusCode());

    verifyZeroInteractions(algorithm);
    verifyZeroInteractions(emailClient);

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verifyZeroInteractions(httpResponse);
    verifyZeroInteractions(httpSession);

    verify(properties).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void recoverWhenIoException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(new IOException("test"));

    assertThat(new AccountImpl(emailClient, httpClient, properties).recover(algorithm, EMAIL))
        .isEqualTo(INTERNAL_SERVER_ERROR.getStatusCode());

    verifyZeroInteractions(algorithm);
    verifyZeroInteractions(emailClient);

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verifyZeroInteractions(httpResponse);
    verifyZeroInteractions(httpSession);

    verify(properties).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void recoverWhenNotOk() throws IOException, InterruptedException {
    when(httpResponse.statusCode()).thenReturn(NO_CONTENT.getStatusCode());

    assertThat(new AccountImpl(emailClient, httpClient, properties).recover(algorithm, EMAIL))
        .isEqualTo(NO_CONTENT.getStatusCode());

    verifyZeroInteractions(algorithm);
    verifyZeroInteractions(emailClient);

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verifyZeroInteractions(httpSession);

    verify(properties).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }
}

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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class AccountTest {
  private static final String EMAIL = "email";
  private static final String ERROR_VERIFY =
      "The account could not be verified, please try again later";
  private static final String FIRST_NAME = "firstName";
  private static final InterruptedException INTERRUPTED_EXCEPTION =
      new InterruptedException("test");
  private static final IOException IO_EXCEPTION = new IOException("test");
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
  private final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
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
    when(httpServletRequest.getSession()).thenReturn(httpSession);
    when(httpServletRequest.getServerName()).thenReturn("localhost");
    when(httpServletRequest.getServerPort()).thenReturn(100);
    when(jsonObject.getString(EMAIL)).thenReturn(EMAIL);
    when(jsonObject.getString(TOKEN)).thenReturn(TOKEN);
    when(jwtVerifier.verify(TOKEN)).thenReturn(decodedJWT);
    when(properties.getProperty(VISUALIZATION)).thenReturn("http://localhost");
    when(properties.getProperty(SMTP_HOST)).thenReturn("localhost");
    when(properties.getProperty(SMTP_PORT)).thenReturn("8080");
  }

  @Test
  void changePassword() throws IOException, InterruptedException {
    assertThat(
            new AccountImpl(httpClient, properties)
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
        .thenThrow(INTERRUPTED_EXCEPTION);

    assertThat(
            new AccountImpl(httpClient, properties)
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
        .thenThrow(IO_EXCEPTION);

    assertThat(
            new AccountImpl(httpClient, properties)
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
        .thenThrow(INTERRUPTED_EXCEPTION);

    assertThat(
            new AccountImpl(httpClient, properties)
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
        .thenThrow(IO_EXCEPTION);

    assertThat(
            new AccountImpl(httpClient, properties)
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
            new AccountImpl(httpClient, properties)
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
            new AccountImpl(httpClient, properties)
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
    assertThat(new AccountImpl(httpClient, properties).logIn(EMAIL, httpSession, SECRET))
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
        .thenThrow(INTERRUPTED_EXCEPTION);

    assertThat(new AccountImpl(httpClient, properties).logIn(EMAIL, httpSession, SECRET))
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
        .thenThrow(IO_EXCEPTION);

    assertThat(new AccountImpl(httpClient, properties).logIn(EMAIL, httpSession, SECRET))
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

    assertThat(new AccountImpl(httpClient, properties).logIn(EMAIL, httpSession, SECRET))
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
        .thenThrow(INTERRUPTED_EXCEPTION);

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
        .thenThrow(IO_EXCEPTION);

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

  @Test
  void signUp() throws IOException, InterruptedException, MessagingException {
    verifySignUpLogIn(OK.getStatusCode());
  }

  @Test
  void signUpWhenEmailErrorLogInIoException()
      throws IOException, InterruptedException, MessagingException {
    doThrow(new MessagingException("test"))
        .when(emailClient)
        .send(
            startsWith(
                "Please verify your account by clicking here: localhost:100/api/account/verify/"),
            any(Message.class),
            eq("Verify"),
            eq(EMAIL),
            any(Transport.class));
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenReturn(httpResponse)
        .thenThrow(IO_EXCEPTION);

    assertThat(
            new AccountImpl(emailClient, httpClient, properties)
                .signUp(algorithm, httpServletRequest, jsonObject))
        .isEqualTo(INTERNAL_SERVER_ERROR.getStatusCode());

    verify(algorithm).getName();
    verify(algorithm).getSigningKeyId();
    verify(algorithm).sign(any(byte[].class), any(byte[].class));
    verifyNoMoreInteractions(algorithm);

    verify(emailClient)
        .send(
            startsWith(
                "Please verify your account by clicking here: localhost:100/api/account/verify/"),
            any(Message.class),
            eq("Verify"),
            eq(EMAIL),
            any(Transport.class));
    verifyNoMoreInteractions(emailClient);

    verify(httpClient, times(2)).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verify(httpServletRequest).getServerName();
    verify(httpServletRequest).getServerPort();
    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);

    verifyZeroInteractions(httpSession);

    verify(jsonObject).getString(EMAIL);
    verify(jsonObject).getString(FIRST_NAME);
    verify(jsonObject).getString(LAST_NAME);
    verify(jsonObject).getString(SECRET);
    verifyNoMoreInteractions(jsonObject);

    verify(properties, times(2)).getProperty(VISUALIZATION);
    verify(properties).getProperty(SMTP_HOST);
    verify(properties).getProperty(SMTP_PORT);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void signUpWhenInterruptedException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(INTERRUPTED_EXCEPTION);

    assertThat(
            new AccountImpl(emailClient, httpClient, properties)
                .signUp(algorithm, httpServletRequest, jsonObject))
        .isEqualTo(INTERNAL_SERVER_ERROR.getStatusCode());

    verifyZeroInteractions(algorithm);
    verifyZeroInteractions(emailClient);

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verifyZeroInteractions(httpResponse);
    verifyZeroInteractions(httpServletRequest);
    verifyZeroInteractions(httpSession);

    verify(jsonObject).getString(EMAIL);
    verify(jsonObject).getString(FIRST_NAME);
    verify(jsonObject).getString(LAST_NAME);
    verify(jsonObject).getString(SECRET);
    verifyNoMoreInteractions(jsonObject);

    verify(properties).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void signUpWhenIoException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(IO_EXCEPTION);

    assertThat(
            new AccountImpl(emailClient, httpClient, properties)
                .signUp(algorithm, httpServletRequest, jsonObject))
        .isEqualTo(INTERNAL_SERVER_ERROR.getStatusCode());

    verifyZeroInteractions(algorithm);
    verifyZeroInteractions(emailClient);

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verifyZeroInteractions(httpResponse);
    verifyZeroInteractions(httpServletRequest);
    verifyZeroInteractions(httpSession);

    verify(jsonObject).getString(EMAIL);
    verify(jsonObject).getString(FIRST_NAME);
    verify(jsonObject).getString(LAST_NAME);
    verify(jsonObject).getString(SECRET);
    verifyNoMoreInteractions(jsonObject);

    verify(properties).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void signUpWhenLogInInterruptedException()
      throws IOException, InterruptedException, MessagingException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenReturn(httpResponse)
        .thenThrow(INTERRUPTED_EXCEPTION);

    assertThat(
            new AccountImpl(emailClient, httpClient, properties)
                .signUp(algorithm, httpServletRequest, jsonObject))
        .isEqualTo(INTERNAL_SERVER_ERROR.getStatusCode());

    verify(algorithm).getName();
    verify(algorithm).getSigningKeyId();
    verify(algorithm).sign(any(byte[].class), any(byte[].class));
    verifyNoMoreInteractions(algorithm);

    verify(emailClient)
        .send(
            startsWith(
                "Please verify your account by clicking here: localhost:100/api/account/verify/"),
            any(Message.class),
            eq("Verify"),
            eq(EMAIL),
            any(Transport.class));
    verifyNoMoreInteractions(emailClient);

    verify(httpClient, times(2)).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verify(httpServletRequest).getServerName();
    verify(httpServletRequest).getServerPort();
    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);

    verifyZeroInteractions(httpSession);

    verify(jsonObject).getString(EMAIL);
    verify(jsonObject).getString(FIRST_NAME);
    verify(jsonObject).getString(LAST_NAME);
    verify(jsonObject).getString(SECRET);
    verifyNoMoreInteractions(jsonObject);

    verify(properties, times(2)).getProperty(VISUALIZATION);
    verify(properties).getProperty(SMTP_HOST);
    verify(properties).getProperty(SMTP_PORT);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void signUpWhenLogInNotOk() throws IOException, InterruptedException, MessagingException {
    when(httpResponse.statusCode()).thenReturn(OK.getStatusCode(), NO_CONTENT.getStatusCode());

    assertThat(
            new AccountImpl(emailClient, httpClient, properties)
                .signUp(algorithm, httpServletRequest, jsonObject))
        .isEqualTo(NO_CONTENT.getStatusCode());

    verify(algorithm).getName();
    verify(algorithm).getSigningKeyId();
    verify(algorithm).sign(any(byte[].class), any(byte[].class));
    verifyNoMoreInteractions(algorithm);

    verify(emailClient)
        .send(
            startsWith(
                "Please verify your account by clicking here: localhost:100/api/account/verify/"),
            any(Message.class),
            eq("Verify"),
            eq(EMAIL),
            any(Transport.class));
    verifyNoMoreInteractions(emailClient);

    verify(httpClient, times(2)).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(httpResponse, times(2)).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verify(httpServletRequest).getServerName();
    verify(httpServletRequest).getServerPort();
    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);

    verifyZeroInteractions(httpSession);

    verify(jsonObject).getString(EMAIL);
    verify(jsonObject).getString(FIRST_NAME);
    verify(jsonObject).getString(LAST_NAME);
    verify(jsonObject).getString(SECRET);
    verifyNoMoreInteractions(jsonObject);

    verify(properties, times(2)).getProperty(VISUALIZATION);
    verify(properties).getProperty(SMTP_HOST);
    verify(properties).getProperty(SMTP_PORT);
    verifyNoMoreInteractions(properties);
  }

  @Test
  void signUpWhenNotOk() throws IOException, InterruptedException {
    when(httpResponse.statusCode()).thenReturn(NO_CONTENT.getStatusCode());
    verifySignUpNoLogIn(NO_CONTENT.getStatusCode());
  }

  @Test
  void verifyAccount() throws IOException, InterruptedException {
    verifyVerifyNoException("The account have been verified");
  }

  @Test
  void verifyWhenInterruptedException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(INTERRUPTED_EXCEPTION);
    verifyVerifyException();
  }

  @Test
  void verifyWhenIoException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(IO_EXCEPTION);
    verifyVerifyException();
  }

  @Test
  void verifyWhenNotOk() throws IOException, InterruptedException {
    when(httpResponse.statusCode()).thenReturn(NO_CONTENT.getStatusCode());
    verifyVerifyNoException(ERROR_VERIFY);
  }

  private void verifySignUp(int statusCode, int times) throws IOException, InterruptedException {
    assertThat(
            new AccountImpl(emailClient, httpClient, properties)
                .signUp(algorithm, httpServletRequest, jsonObject))
        .isEqualTo(statusCode);

    verify(httpClient, times(times)).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    if (times == 2) verify(httpResponse).body();
    verify(httpResponse, times(times)).statusCode();
    verifyNoMoreInteractions(httpResponse);

    verify(jsonObject).getString(EMAIL);
    verify(jsonObject).getString(FIRST_NAME);
    verify(jsonObject).getString(LAST_NAME);
    verify(jsonObject).getString(SECRET);
    verifyNoMoreInteractions(jsonObject);

    verify(properties, times(times)).getProperty(VISUALIZATION);

    if (times == 2) {
      verify(properties).getProperty(SMTP_HOST);
      verify(properties).getProperty(SMTP_PORT);
    }

    verifyNoMoreInteractions(properties);
  }

  private void verifySignUpLogIn(int statusCode)
      throws MessagingException, IOException, InterruptedException {
    verifySignUp(statusCode, 2);

    verify(algorithm).getName();
    verify(algorithm).getSigningKeyId();
    verify(algorithm).sign(any(byte[].class), any(byte[].class));
    verifyNoMoreInteractions(algorithm);

    verify(emailClient)
        .send(
            startsWith(
                "Please verify your account by clicking here: localhost:100/api/account/verify/"),
            any(Message.class),
            eq("Verify"),
            eq(EMAIL),
            any(Transport.class));
    verifyNoMoreInteractions(emailClient);

    verify(httpServletRequest).getServerName();
    verify(httpServletRequest).getServerPort();
    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);

    verify(httpSession).setAttribute(EMAIL, EMAIL);
    verify(httpSession).setAttribute(FIRST_NAME, FIRST_NAME);
    verify(httpSession).setAttribute("id", "123");
    verify(httpSession).setAttribute(LAST_NAME, LAST_NAME);
    verifyNoMoreInteractions(httpSession);
  }

  private void verifySignUpNoLogIn(int statusCode) throws IOException, InterruptedException {
    verifySignUp(statusCode, 1);

    verifyZeroInteractions(algorithm);
    verifyZeroInteractions(emailClient);
    verifyZeroInteractions(httpServletRequest);
    verifyZeroInteractions(httpSession);
  }

  private void verifyVerify(String message) throws IOException, InterruptedException {
    assertThat(new AccountImpl(httpClient, properties).verify(EMAIL)).isEqualTo(message);

    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(properties).getProperty(VISUALIZATION);
    verifyNoMoreInteractions(properties);
  }

  private void verifyVerifyException() throws IOException, InterruptedException {
    verifyVerify(ERROR_VERIFY);
    verifyZeroInteractions(httpResponse);
  }

  private void verifyVerifyNoException(String message) throws IOException, InterruptedException {
    verifyVerify(message);

    verify(httpResponse).statusCode();
    verifyNoMoreInteractions(httpResponse);
  }
}

package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static io.github.henryssondaniel.teacup.visualization.back.v1._0.Utils.handleException;
import static java.lang.String.join;
import static javax.ws.rs.core.Response.Status.FORBIDDEN;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.JWTVerifier;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Objects;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;
import org.json.JSONObject;

class AccountImpl implements Account {
  private static final String AUTHORIZED = "authorized";
  private static final String CHANGE_SECRET = "changePassword";
  private static final CharSequence DELIMITER = ", ";
  private static final String EMAIL = "email";
  private static final String ERROR_CHANGE_SECRET = "Could not change the password";
  private static final String ERROR_LOG_IN = "Could not log in";
  private static final String ERROR_RECOVER = "Could not recover the account";
  private static final String ERROR_SIGN_UP = "Could not sign up";
  private static final String ERROR_VERIFY = "Could not verify the account";
  private static final String FIRST_NAME = "firstName";
  private static final String ID = "id";
  private static final String LAST_NAME = "lastName";
  private static final Logger LOGGER = Logger.getLogger(AccountImpl.class.getName());
  private static final String LOG_IN = "logIn";
  private static final String PATH = "api/account/";
  private static final String RECOVER = "recover";
  private static final String SECRET = "password";
  private static final String TOKEN = "token";
  private static final String VISUALIZATION = "service.visualization";

  private final EmailClient emailClient;
  private final HttpClient httpClient;
  private final Properties properties;

  AccountImpl(EmailClient emailClient, HttpClient httpClient, Properties properties) {
    this.emailClient = emailClient;
    this.httpClient = httpClient;
    this.properties = new Properties(properties);
  }

  AccountImpl(HttpClient httpClient, Properties properties) {
    this(new EmailClientImpl(properties), httpClient, properties);
  }

  @Override
  public ResponseBuilder changePassword(
      HttpSession httpSession, JSONObject jsonObject, JWTVerifier jwtVerifier) {
    ResponseBuilder responseBuilder;

    try {
      responseBuilder =
          Response.status(
              changePasswordRequest(
                  jwtVerifier.verify(jsonObject.getString(TOKEN)).getClaim(EMAIL).asString(),
                  httpSession,
                  jsonObject.getString(SECRET)));
    } catch (JWTVerificationException e) {
      LOGGER.log(Level.SEVERE, "The token could not be verified", e);
      responseBuilder = Response.status(FORBIDDEN);
    }

    return responseBuilder;
  }

  @Override
  public int logIn(String email, HttpSession httpSession, String password) {
    LOGGER.log(Level.FINE, "Log in");

    int statusCode;

    try {
      var httpResponse =
          sendRequest(
              httpClient,
              createHttpRequest(
                  join(DELIMITER, createJson(EMAIL, email), createJson(SECRET, password)), LOG_IN));

      statusCode = httpResponse.statusCode();

      if (statusCode == Status.OK.getStatusCode()) {
        var jsonObject = new JSONObject(httpResponse.body());

        httpSession.setAttribute(EMAIL, jsonObject.getString(EMAIL));
        httpSession.setAttribute(FIRST_NAME, jsonObject.getString(FIRST_NAME));
        httpSession.setAttribute(ID, jsonObject.getString(ID));
        httpSession.setAttribute(LAST_NAME, jsonObject.getString(LAST_NAME));
      }
    } catch (IOException e) {
      statusCode = handleException(ERROR_LOG_IN, e);
    } catch (InterruptedException e) {
      statusCode = handleException(ERROR_LOG_IN, e);
      Thread.currentThread().interrupt();
    }

    return statusCode;
  }

  @Override
  public int recover(Algorithm algorithm, String email) {
    LOGGER.log(Level.FINE, "Recover");

    int statusCode;

    try {
      statusCode =
          sendRequest(httpClient, createHttpRequest(createJson(EMAIL, email), RECOVER))
              .statusCode();

      if (statusCode == Status.OK.getStatusCode())
        sendEmail(
            "The recover code: "
                + JWT.create()
                    .withClaim(EMAIL, email)
                    .withExpiresAt(Date.from(Instant.now().plus(1L, ChronoUnit.HOURS)))
                    .sign(algorithm),
            "Recover",
            email);
    } catch (IOException e) {
      statusCode = handleException(ERROR_RECOVER, e);
    } catch (InterruptedException e) {
      statusCode = handleException(ERROR_RECOVER, e);
      Thread.currentThread().interrupt();
    }

    return statusCode;
  }

  @Override
  public int signUp(
      Algorithm algorithm, HttpServletRequest httpServletRequest, JSONObject jsonObject) {
    LOGGER.log(Level.FINE, "Sign up");

    int statusCode;

    var email = jsonObject.getString(EMAIL);
    var password = jsonObject.getString(SECRET);

    try {
      statusCode =
          sendRequest(
                  httpClient,
                  createHttpRequest(
                      join(
                          DELIMITER,
                          createJson(EMAIL, email),
                          createJson(FIRST_NAME, jsonObject.getString(FIRST_NAME)),
                          createJson(LAST_NAME, jsonObject.getString(LAST_NAME)),
                          createJson(SECRET, password)),
                      "signUp"))
              .statusCode();

      if (statusCode == Status.OK.getStatusCode()) {
        sendEmail(
            "Please verify your account by clicking here: "
                + httpServletRequest.getServerName()
                + ':'
                + httpServletRequest.getServerPort()
                + '/'
                + PATH
                + "verify/"
                + JWT.create().withClaim(EMAIL, email).sign(algorithm),
            "Verify",
            email);

        statusCode = logIn(email, httpServletRequest.getSession(), password);
      }
    } catch (IOException e) {
      statusCode = handleException(ERROR_SIGN_UP, e);
    } catch (InterruptedException e) {
      statusCode = handleException(ERROR_SIGN_UP, e);
      Thread.currentThread().interrupt();
    }

    return statusCode;
  }

  @Override
  public String verify(String email) {
    String data = null;

    try {
      var statusCode =
          sendRequest(httpClient, createHttpRequest(createJson(EMAIL, email), "verify"))
              .statusCode();

      if (statusCode == Status.OK.getStatusCode()) data = "The account have been verified";
    } catch (IOException e) {
      LOGGER.log(Level.SEVERE, ERROR_VERIFY, e);
    } catch (InterruptedException e) {
      LOGGER.log(Level.SEVERE, ERROR_VERIFY, e);
      Thread.currentThread().interrupt();
    }

    return Objects.requireNonNullElse(
        data, "The account could not be verified, please try again later");
  }

  private int changePasswordRequest(String email, HttpSession httpSession, String password) {
    int statusCode;

    try {
      statusCode =
          sendRequest(
                  httpClient,
                  createHttpRequest(
                      join(
                          DELIMITER,
                          createKeyValue(AUTHORIZED, false),
                          createJson(EMAIL, email),
                          createJson(SECRET, password)),
                      CHANGE_SECRET))
              .statusCode();

      if (statusCode == Status.OK.getStatusCode()) statusCode = logIn(email, httpSession, password);
    } catch (IOException e) {
      statusCode = handleException(ERROR_CHANGE_SECRET, e);
    } catch (InterruptedException e) {
      statusCode = handleException(ERROR_CHANGE_SECRET, e);
      Thread.currentThread().interrupt();
    }

    return statusCode;
  }

  private HttpRequest createHttpRequest(String body, String path) {
    return HttpRequest.newBuilder()
        .POST(BodyPublishers.ofString('{' + body + '}'))
        .setHeader("content-type", "application/json")
        .uri(URI.create(properties.getProperty(VISUALIZATION) + '/' + PATH + path))
        .build();
  }

  private static String createJson(String key, String value) {
    return createKeyValue(key, '"' + value + '"');
  }

  private static String createKeyValue(String key, Object value) {
    return '"' + key + "\": " + value;
  }

  private void sendEmail(String content, String subject, String to) {
    var smtpProperties = new Properties();
    smtpProperties.setProperty("mail.smtp.host", properties.getProperty("smtp.host"));
    smtpProperties.setProperty("mail.smtp.port", properties.getProperty("smtp.port"));

    var session = Session.getInstance(smtpProperties);

    try (var transport = session.getTransport("smtp")) {
      emailClient.send(content, new MimeMessage(session), subject, to, transport);
    } catch (MessagingException e) {
      LOGGER.log(Level.SEVERE, "Could not send the email", e);
    }
  }

  private static HttpResponse<String> sendRequest(HttpClient httpClient, HttpRequest httpRequest)
      throws IOException, InterruptedException {
    return httpClient.send(httpRequest, BodyHandlers.ofString());
  }
}

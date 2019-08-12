package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static io.github.henryssondaniel.teacup.visualization.back.v1._0.Utils.allowCredentials;
import static io.github.henryssondaniel.teacup.visualization.back.v1._0.Utils.handleException;
import static io.github.henryssondaniel.teacup.visualization.back.v1._0.Utils.userRequired;
import static java.lang.String.join;
import static javax.ws.rs.core.Response.Status.FORBIDDEN;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.JWTVerifier;
import io.github.henryssondaniel.teacup.core.configuration.Factory;
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
import java.util.Optional;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.mail.Message;
import javax.mail.Message.RecipientType;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;
import org.json.JSONObject;

/**
 * Account resource. Handles account related requests.
 *
 * @since 1.0
 */
@Path("{a:v1/account|v1.0/account|account}")
public class AccountResource {
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
  private static final Logger LOGGER = Logger.getLogger(AccountResource.class.getName());
  private static final String LOG_IN = "logIn";
  private static final String PATH = "api/account/";
  private static final Properties PROPERTIES_CORE = Factory.getProperties();
  private static final String RECOVER = "recover";
  private static final String SECRET = "password";
  private static final String TOKEN = "token";

  private final HttpClient httpClient;
  private final Properties properties;

  private Algorithm algorithm;
  private JWTVerifier jwtVerifier;
  private Transport transport;

  public AccountResource() {
    this(null, HttpClient.newHttpClient(), null, PROPERTIES_CORE, null);
  }

  AccountResource(
      Algorithm algorithm,
      HttpClient httpClient,
      JWTVerifier jwtVerifier,
      Properties properties,
      Transport transport) {
    this.algorithm = algorithm;
    this.httpClient = httpClient;
    this.jwtVerifier = jwtVerifier;
    this.properties = new Properties(properties);
    this.transport = transport;
  }

  /**
   * Authorized.
   *
   * @return the response
   * @since 1.0
   */
  @GET
  @Path(AUTHORIZED)
  @Produces(MediaType.APPLICATION_JSON)
  public static Response authorized(@Context HttpServletRequest httpServletRequest) {
    LOGGER.log(Level.FINE, "Authorized");

    return allowCredentials(userRequired(httpServletRequest.getSession()).orElseGet(Response::ok));
  }

  /**
   * Change password.
   *
   * @return the response
   * @since 1.0
   */
  @POST
  @Path(CHANGE_SECRET)
  @Produces(MediaType.APPLICATION_JSON)
  public Response changePassword(String data, @Context HttpServletRequest httpServletRequest) {
    LOGGER.log(Level.FINE, "Change password");

    var httpSession = httpServletRequest.getSession();
    return allowCredentials(
        noUserRequired(httpSession)
            .orElseGet(() -> changePassword(httpSession, new JSONObject(data))));
  }

  /**
   * Log in.
   *
   * @return the response
   * @since 1.0
   */
  @POST
  @Path(LOG_IN)
  @Produces(MediaType.APPLICATION_JSON)
  public Response logIn(String data, @Context HttpServletRequest httpServletRequest) {
    LOGGER.log(Level.FINE, "Log in");

    var httpSession = httpServletRequest.getSession();
    return allowCredentials(
        noUserRequired(httpSession)
            .orElseGet(
                () -> {
                  var jsonObject = new JSONObject(data);
                  return Response.status(
                      logIn(
                          jsonObject.getString(EMAIL), httpSession, jsonObject.getString(SECRET)));
                }));
  }

  /**
   * Log out.
   *
   * @return the response
   * @since 1.0
   */
  @POST
  @Path("logOut")
  @Produces(MediaType.APPLICATION_JSON)
  public static Response logOut(@Context HttpServletRequest httpServletRequest) {
    LOGGER.log(Level.FINE, "Log in");

    var httpSession = httpServletRequest.getSession();
    return allowCredentials(
        userRequired(httpSession)
            .orElseGet(
                () -> {
                  httpSession.invalidate();
                  return Response.ok();
                }));
  }

  /**
   * Recover.
   *
   * @return the response
   * @since 1.0
   */
  @POST
  @Path(RECOVER)
  @Produces(MediaType.APPLICATION_JSON)
  public Response recover(String data, @Context HttpServletRequest httpServletRequest) {
    LOGGER.log(Level.FINE, "Recover");

    return allowCredentials(
        noUserRequired(httpServletRequest.getSession())
            .orElseGet(() -> Response.status(recover(new JSONObject(data).getString(EMAIL)))));
  }

  /**
   * Sign up.
   *
   * @return the response
   * @since 1.0
   */
  @POST
  @Path("signUp")
  @Produces(MediaType.APPLICATION_JSON)
  public Response signUp(String data, @Context HttpServletRequest httpServletRequest) {
    LOGGER.log(Level.FINE, "Sign up");

    return allowCredentials(
        noUserRequired(httpServletRequest.getSession())
            .orElseGet(() -> Response.status(signUp(httpServletRequest, new JSONObject(data)))));
  }

  /**
   * Verify.
   *
   * @return the response
   * @since 1.0
   */
  @GET
  @Path("verify/{token}")
  @Produces(MediaType.TEXT_PLAIN)
  public String verify(@PathParam(TOKEN) String token) {
    LOGGER.log(Level.FINE, "Verify");

    String data;

    try {
      data = verifyAccount(getJwtVerifier().verify(token).getClaim(EMAIL).asString());
    } catch (JWTVerificationException e) {
      LOGGER.log(Level.SEVERE, "The token could not be verified", e);
      data = "The token is not valid";
    }

    return data;
  }

  private ResponseBuilder changePassword(HttpSession httpSession, JSONObject jsonObject) {
    ResponseBuilder responseBuilder;

    try {
      responseBuilder =
          Response.status(
              changePasswordRequest(
                  getJwtVerifier().verify(jsonObject.getString(TOKEN)).getClaim(EMAIL).asString(),
                  httpSession,
                  jsonObject.getString(SECRET)));
    } catch (JWTVerificationException e) {
      LOGGER.log(Level.SEVERE, "The token could not be verified", e);
      responseBuilder = Response.status(FORBIDDEN);
    }

    return responseBuilder;
  }

  private int changePasswordRequest(String email, HttpSession httpSession, String password) {
    int statusCode;

    try {
      statusCode =
          sendRequest(
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
        .uri(URI.create(properties.getProperty("service.visualization") + '/' + PATH + path))
        .build();
  }

  private static String createJson(String key, String value) {
    return createKeyValue(key, '"' + value + '"');
  }

  private static String createKeyValue(String key, Object value) {
    return '"' + key + "\": " + value;
  }

  private Algorithm getAlgorithm() {
    if (algorithm == null) algorithm = Algorithm.HMAC256(properties.getProperty("secret.key"));

    return algorithm;
  }

  private JWTVerifier getJwtVerifier() {
    if (jwtVerifier == null) jwtVerifier = JWT.require(getAlgorithm()).build();

    return jwtVerifier;
  }

  private int logIn(String email, HttpSession httpSession, String password) {
    int statusCode;

    try {
      var httpResponse =
          sendRequest(
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

  private static Optional<ResponseBuilder> noUserRequired(HttpSession httpSession) {
    return Optional.ofNullable(
        httpSession.getAttribute(ID) == null ? null : Response.status(Status.UNAUTHORIZED));
  }

  private int recover(String email) {
    int statusCode;

    try {
      statusCode = sendRequest(createHttpRequest(createJson(EMAIL, email), RECOVER)).statusCode();

      if (statusCode == Status.OK.getStatusCode())
        sendEmail(
            "The recover code: "
                + JWT.create()
                    .withClaim(EMAIL, email)
                    .withExpiresAt(Date.from(Instant.now().plus(1L, ChronoUnit.HOURS)))
                    .sign(getAlgorithm()),
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

  private void sendEmail(String content, String subject, String to) {
    var smtpProperties = new Properties();
    smtpProperties.setProperty("mail.smtp.host", properties.getProperty("smtp.host"));
    smtpProperties.setProperty("mail.smtp.port", properties.getProperty("smtp.port"));

    var session = Session.getInstance(smtpProperties);

    Message message = new MimeMessage(session);

    try {
      message.setFrom(new InternetAddress(properties.getProperty("smtp.from")));
      message.setRecipients(RecipientType.TO, InternetAddress.parse(to));
      message.setSubject(subject + " your Teacup account");
      message.setText(content);

      if (transport == null) transport = session.getTransport("smtp");

      transport.connect();
      transport.sendMessage(message, message.getAllRecipients());
      transport.close();
    } catch (MessagingException e) {
      LOGGER.log(Level.SEVERE, "Could not send the email", e);
    }
  }

  private HttpResponse<String> sendRequest(HttpRequest httpRequest)
      throws IOException, InterruptedException {
    return httpClient.send(httpRequest, BodyHandlers.ofString());
  }

  private int signUp(HttpServletRequest httpServletRequest, JSONObject jsonObject) {
    int statusCode;

    var email = jsonObject.getString(EMAIL);
    var password = jsonObject.getString(SECRET);

    try {
      statusCode =
          sendRequest(
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
                + JWT.create().withClaim(EMAIL, email).sign(getAlgorithm()),
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

  private String verifyAccount(String email) {
    String data = null;

    try {
      var statusCode =
          sendRequest(createHttpRequest(createJson(EMAIL, email), "verify")).statusCode();

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
}

package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static io.github.henryssondaniel.teacup.visualization.back.v1._0.Utils.allowCredentials;
import static io.github.henryssondaniel.teacup.visualization.back.v1._0.Utils.userRequired;
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
  private static final String EMAIL = "email";
  private static final String FIRST_NAME = "firstName";
  private static final String ID = "id";
  private static final String JSON_EMAIL = "\"email\": \"%s\"";
  private static final String JSON_PASSWORD = "\"password\": \"%s\"";
  private static final String LAST_NAME = "lastName";
  private static final Logger LOGGER = Logger.getLogger(AccountResource.class.getName());
  private static final String LOG_IN = "logIn";
  private static final String PASSWORD = "password";
  private static final Properties PROPERTIES = Factory.getProperties();
  private static final String RECOVER = "recover";
  private static final String TOKEN = "token";

  private Algorithm algorithm;
  private JWTVerifier jwtVerifier;

  /**
   * Authorized.
   *
   * @return the response
   * @since 1.0
   */
  @GET
  @Path("authorized")
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
  @Path("changePassword")
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
  public static Response logIn(String data, @Context HttpServletRequest httpServletRequest) {
    LOGGER.log(Level.FINE, "Log in");

    var httpSession = httpServletRequest.getSession();
    return allowCredentials(
        noUserRequired(httpSession)
            .orElseGet(
                () -> {
                  var jsonObject = new JSONObject(data);
                  return Response.status(
                      logIn(
                          jsonObject.getString(EMAIL),
                          jsonObject.getString(PASSWORD),
                          httpSession));
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
    return allowCredentials(userRequired(httpSession).orElseGet(() -> logOut(httpSession)));
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

    String message;

    try {
      message = verifyAccount(getJwtVerifier().verify(token).getClaim(EMAIL).asString());
    } catch (JWTVerificationException e) {
      LOGGER.log(Level.SEVERE, "The token could not be verified", e);
      message = "The token is not valid";
    }

    return message;
  }

  private static HttpRequest buildHttpRequest(String body, String path) {
    return HttpRequest.newBuilder()
        .POST(BodyPublishers.ofString('{' + body + '}'))
        .setHeader("content-type", "application/json")
        .uri(URI.create(PROPERTIES.getProperty("service.visualization") + path))
        .build();
  }

  private ResponseBuilder changePassword(HttpSession httpSession, JSONObject jsonObject) {
    ResponseBuilder responseBuilder;

    try {
      responseBuilder =
          Response.status(
              changePasswordRequest(
                  getJwtVerifier().verify(jsonObject.getString(TOKEN)).getClaim(EMAIL).asString(),
                  jsonObject.getString(PASSWORD),
                  httpSession));
    } catch (JWTVerificationException e) {
      LOGGER.log(Level.SEVERE, "The token could not be verified", e);
      responseBuilder = Response.status(FORBIDDEN);
    }

    return responseBuilder;
  }

  private static int changePasswordRequest(String email, String password, HttpSession httpSession) {
    int statusCode;

    try {
      var httpResponse = sendRequest(createHttpRequest(false, email, password, "changePassword"));

      statusCode = httpResponse.statusCode();

      if (statusCode == Status.OK.getStatusCode()) logIn(email, password, httpSession);
    } catch (IOException | InterruptedException e) {
      LOGGER.log(Level.SEVERE, "Could not change the password", e);
      statusCode = Status.INTERNAL_SERVER_ERROR.getStatusCode();
    }

    return statusCode;
  }

  private static HttpRequest createHttpRequest(String email, String path) {
    return createHttpRequest(email, null, path);
  }

  private static HttpRequest createHttpRequest(String email, String password, String path) {
    return createHttpRequest(null, email, password, path);
  }

  private static HttpRequest createHttpRequest(
      Boolean authorized, String email, String password, String path) {
    var body = new StringBuilder(0);

    if (authorized != null) body.append("\"authorized\": ").append(authorized).append(", ");

    body.append(String.format(JSON_EMAIL, email));

    if (password != null) body.append(", ").append(String.format(JSON_PASSWORD, password));

    return buildHttpRequest(body.toString(), "/api/account/" + path);
  }

  private Algorithm getAlgorithm() {
    if (algorithm == null) algorithm = Algorithm.HMAC256(PROPERTIES.getProperty("secret.key"));

    return algorithm;
  }

  private JWTVerifier getJwtVerifier() {
    if (jwtVerifier == null) jwtVerifier = JWT.require(getAlgorithm()).build();

    return jwtVerifier;
  }

  private static int logIn(String email, String password, HttpSession httpSession) {
    int statusCode;

    try {
      var httpResponse = sendRequest(createHttpRequest(email, password, LOG_IN));

      statusCode = httpResponse.statusCode();

      if (statusCode == Status.OK.getStatusCode()) {
        var jsonObject = new JSONObject(httpResponse.body());

        httpSession.setAttribute(EMAIL, jsonObject.getString(EMAIL));
        httpSession.setAttribute(FIRST_NAME, jsonObject.getString(FIRST_NAME));
        httpSession.setAttribute(ID, jsonObject.getString(ID));
        httpSession.setAttribute(LAST_NAME, jsonObject.getString(LAST_NAME));
      }
    } catch (IOException | InterruptedException e) {
      LOGGER.log(Level.SEVERE, "Could not log in", e);
      statusCode = Status.INTERNAL_SERVER_ERROR.getStatusCode();
    }

    return statusCode;
  }

  private static ResponseBuilder logOut(HttpSession httpSession) {
    httpSession.invalidate();

    return Response.ok();
  }

  private static Optional<ResponseBuilder> noUserRequired(HttpSession httpSession) {
    return Optional.ofNullable(
        httpSession.getAttribute(ID) == null ? null : Response.status(Status.UNAUTHORIZED));
  }

  private int recover(String email) {
    int statusCode;

    try {
      var httpResponse = sendRequest(createHttpRequest(email, RECOVER));

      statusCode = httpResponse.statusCode();

      if (statusCode == Status.OK.getStatusCode())
        sendEmail(
            "The recover code: "
                + JWT.create()
                    .withClaim(EMAIL, email)
                    .withExpiresAt(Date.from(Instant.now().plus(1L, ChronoUnit.HOURS)))
                    .sign(getAlgorithm()),
            "Recover",
            email);
    } catch (IOException | InterruptedException e) {
      LOGGER.log(Level.SEVERE, "Could not recover the account", e);
      statusCode = Status.INTERNAL_SERVER_ERROR.getStatusCode();
    }

    return statusCode;
  }

  private static void sendEmail(String content, String subject, String to) {
    var properties = new Properties();
    properties.setProperty("mail.smtp.host", PROPERTIES.getProperty("SMTP_HOST"));
    properties.setProperty("mail.smtp.port", PROPERTIES.getProperty("SMTP_PORT"));

    try {
      Message message = new MimeMessage(Session.getInstance(properties));
      message.setFrom(new InternetAddress(PROPERTIES.getProperty("SMTP_FROM")));
      message.setRecipients(RecipientType.TO, InternetAddress.parse(to));
      message.setSubject(subject + " your Teacup account");
      message.setText(content);

      Transport.send(message);
    } catch (MessagingException e) {
      LOGGER.log(Level.SEVERE, "Could not send the email", e);
    }
  }

  private static HttpResponse<String> sendRequest(HttpRequest httpRequest)
      throws IOException, InterruptedException {
    return HttpClient.newHttpClient().send(httpRequest, BodyHandlers.ofString());
  }

  private int signUp(HttpServletRequest httpServletRequest, JSONObject jsonObject) {
    int statusCode;

    var email = jsonObject.getString(EMAIL);
    var password = jsonObject.getString(PASSWORD);

    try {
      var httpResponse =
          HttpClient.newHttpClient()
              .send(
                  HttpRequest.newBuilder()
                      .POST(
                          BodyPublishers.ofString(
                              "{\"email\": \""
                                  + email
                                  + "\", \"firstName\": \""
                                  + jsonObject.getString(FIRST_NAME)
                                  + "\", \"lastName\": \""
                                  + jsonObject.getString(LAST_NAME)
                                  + "\", "
                                  + String.format(JSON_PASSWORD, password)
                                  + '}'))
                      .setHeader("content-type", "application/json")
                      .uri(
                          URI.create(
                              PROPERTIES.getProperty("service.visualization")
                                  + "/api/account/signUp"))
                      .build(),
                  BodyHandlers.ofString());

      statusCode = httpResponse.statusCode();

      if (statusCode == Status.OK.getStatusCode()) {
        sendEmail(
            "Please verify your account by clicking here: "
                + httpServletRequest.getServerName()
                + ':'
                + httpServletRequest.getServerPort()
                + "/api/account/verify/"
                + JWT.create().withClaim(EMAIL, email).sign(getAlgorithm()),
            "Verify",
            email);

        statusCode = logIn(email, password, httpServletRequest.getSession());
      }
    } catch (IOException | InterruptedException e) {
      LOGGER.log(Level.SEVERE, "Could not sign up", e);
      statusCode = Status.INTERNAL_SERVER_ERROR.getStatusCode();
    }

    return statusCode;
  }

  private static String verifyAccount(String email) {
    String message = null;

    try {
      var httpResponse = sendRequest(createHttpRequest(email, "verify"));

      var statusCode = httpResponse.statusCode();

      if (statusCode == Status.OK.getStatusCode()) message = "The account have been verified";
    } catch (IOException | InterruptedException e) {
      LOGGER.log(Level.SEVERE, "Could not verify the account", e);
    }

    return Objects.requireNonNullElse(
        message, "The account could not be verified, please try again later");
  }
}

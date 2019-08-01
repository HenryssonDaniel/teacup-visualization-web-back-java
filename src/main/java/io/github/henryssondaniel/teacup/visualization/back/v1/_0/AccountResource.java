package io.github.henryssondaniel.teacup.visualization.back.v1._0;

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
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
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
  private static final Logger LOGGER = Logger.getLogger(AccountResource.class.getName());
  private static final Properties PROPERTIES = Factory.getProperties();

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

    return Utils.userRequired(httpServletRequest.getSession()).orElseGet(Response::ok).build();
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
  public Response changePassword(
      @Context HttpServletRequest httpServletRequest,
      @QueryParam("password") String password,
      @QueryParam("token") String token) {
    LOGGER.log(Level.FINE, "Change password");

    var httpSession = httpServletRequest.getSession();

    return noUserRequired(httpSession)
        .orElseGet(() -> changePassword(password, token, httpSession))
        .build();
  }

  /**
   * Log in.
   *
   * @return the response
   * @since 1.0
   */
  @POST
  @Path("logIn")
  @Produces(MediaType.APPLICATION_JSON)
  public static Response logIn(
      @Context HttpServletRequest httpServletRequest,
      @QueryParam("email") String email,
      @QueryParam("password") String password) {
    LOGGER.log(Level.FINE, "Log in");

    var httpSession = httpServletRequest.getSession();
    return noUserRequired(httpSession)
        .orElseGet(() -> Response.status(logIn(email, password, httpSession)))
        .build();
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
    return Utils.userRequired(httpSession).orElseGet(() -> logOut(httpSession)).build();
  }

  /**
   * Recover.
   *
   * @return the response
   * @since 1.0
   */
  @POST
  @Path("recover")
  @Produces(MediaType.APPLICATION_JSON)
  public static Response recover(
      @Context HttpServletRequest httpServletRequest, @QueryParam("email") String email) {
    LOGGER.log(Level.FINE, "Recover");

    return noUserRequired(httpServletRequest.getSession())
        .orElseGet(() -> Response.status(recover(email)))
        .build();
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
  public static Response signUp(
      @Context HttpServletRequest httpServletRequest,
      @QueryParam("email") String email,
      @QueryParam("password") String password) {
    LOGGER.log(Level.FINE, "Sign up");

    var httpSession = httpServletRequest.getSession();

    return noUserRequired(httpSession)
        .orElseGet(() -> Response.status(signUp(email, password, httpSession)))
        .build();
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
  public String verify(@PathParam("token") String token) {
    LOGGER.log(Level.FINE, "Verify");

    String message;

    try {
      message = verifyAccount(getJwtVerifier().verify(token).getClaim("email").asString());
    } catch (JWTVerificationException e) {
      LOGGER.log(Level.SEVERE, "The token could not be verified", e);
      message = "The token is not valid";
    }

    return message;
  }

  private ResponseBuilder changePassword(String password, String token, HttpSession httpSession) {
    ResponseBuilder responseBuilder;

    try {
      responseBuilder =
          Response.status(
              changePasswordRequest(
                  getJwtVerifier().verify(token).getClaim("email").asString(),
                  password,
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
      var httpResponse =
          HttpClient.newHttpClient()
              .send(
                  HttpRequest.newBuilder()
                      .POST(
                          BodyPublishers.ofString(
                              "{\"authorized\": false, \"email\": \""
                                  + email
                                  + "\", \"password\": "
                                  + password
                                  + "\"}"))
                      .setHeader("content-type", "application/json")
                      .uri(
                          URI.create(
                              PROPERTIES.getProperty("service.visualization")
                                  + "/api/account/changePassword"))
                      .build(),
                  BodyHandlers.ofString());

      statusCode = httpResponse.statusCode();

      if (statusCode == Status.OK.getStatusCode()) logIn(email, password, httpSession);
    } catch (IOException | InterruptedException e) {
      LOGGER.log(Level.SEVERE, "Could not change the password", e);
      statusCode = Status.INTERNAL_SERVER_ERROR.getStatusCode();
    }

    return statusCode;
  }

  private Algorithm getAlgorithm() {
    if (null == algorithm) algorithm = Algorithm.HMAC256(PROPERTIES.getProperty("secret.key"));

    return algorithm;
  }

  private JWTVerifier getJwtVerifier() {
    if (null == jwtVerifier) jwtVerifier = JWT.require(getAlgorithm()).build();

    return jwtVerifier;
  }

  private static int logIn(String email, String password, HttpSession httpSession) {
    int statusCode;

    try {
      var httpResponse =
          HttpClient.newHttpClient()
              .send(
                  HttpRequest.newBuilder()
                      .POST(
                          BodyPublishers.ofString(
                              "{\"email\": \"" + email + "\", \"password\": " + password + "\"}"))
                      .setHeader("content-type", "application/json")
                      .uri(
                          URI.create(
                              PROPERTIES.getProperty("service.visualization")
                                  + "/api/account/logIn"))
                      .build(),
                  BodyHandlers.ofString());

      statusCode = httpResponse.statusCode();

      if (statusCode == Status.OK.getStatusCode()) {
        var jsonObject = new JSONObject(httpResponse.body());

        httpSession.setAttribute("email", jsonObject.getString("email"));
        httpSession.setAttribute("firstName", jsonObject.getString("firstName"));
        httpSession.setAttribute("id", jsonObject.getString("id"));
        httpSession.setAttribute("lastName", jsonObject.getString("lastName"));
      }
    } catch (IOException | InterruptedException e) {
      LOGGER.log(Level.SEVERE, "Could not log in", e);
      statusCode = Status.INTERNAL_SERVER_ERROR.getStatusCode();
    }

    return statusCode;
  }

  private static ResponseBuilder logOut(HttpSession httpSession) {
    httpSession.removeAttribute("id");

    return Response.ok();
  }

  private static Optional<ResponseBuilder> noUserRequired(HttpSession httpSession) {
    return Optional.ofNullable(
        null == httpSession.getAttribute("id") ? null : Response.status(Status.UNAUTHORIZED));
  }

  private static int recover(String email) {
    int statusCode;

    try {
      var httpResponse =
          HttpClient.newHttpClient()
              .send(
                  HttpRequest.newBuilder()
                      .POST(BodyPublishers.ofString("{\"email\": \"" + email + "\"}"))
                      .setHeader("content-type", "application/json")
                      .uri(
                          URI.create(
                              PROPERTIES.getProperty("service.visualization")
                                  + "/api/account/recover"))
                      .build(),
                  BodyHandlers.ofString());

      statusCode = httpResponse.statusCode();

      if (statusCode == Status.OK.getStatusCode()) LOGGER.log(Level.FINE, "Send email");
    } catch (IOException | InterruptedException e) {
      LOGGER.log(Level.SEVERE, "Could not recover the account", e);
      statusCode = Status.INTERNAL_SERVER_ERROR.getStatusCode();
    }

    return statusCode;
  }

  private static int signUp(String email, String password, HttpSession httpSession) {
    int statusCode;

    try {
      var httpResponse =
          HttpClient.newHttpClient()
              .send(
                  HttpRequest.newBuilder()
                      .POST(
                          BodyPublishers.ofString(
                              "{\"email\": \""
                                  + email
                                  + "\", \"password\": \" "
                                  + password
                                  + "\"}"))
                      .setHeader("content-type", "application/json")
                      .uri(
                          URI.create(
                              PROPERTIES.getProperty("service.visualization")
                                  + "/api/account/signUp"))
                      .build(),
                  BodyHandlers.ofString());

      statusCode = httpResponse.statusCode();

      if (statusCode == Status.OK.getStatusCode()) {
        LOGGER.log(Level.FINE, "Send email");

        statusCode = logIn(email, password, httpSession);
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
      var httpResponse =
          HttpClient.newHttpClient()
              .send(
                  HttpRequest.newBuilder()
                      .POST(BodyPublishers.ofString("{\"email\": \"" + email + "\"}"))
                      .setHeader("content-type", "application/json")
                      .uri(
                          URI.create(
                              PROPERTIES.getProperty("service.visualization")
                                  + "/api/account/verify"))
                      .build(),
                  BodyHandlers.ofString());

      var statusCode = httpResponse.statusCode();

      if (statusCode == Status.OK.getStatusCode()) message = "The account have been verified";
    } catch (IOException | InterruptedException e) {
      LOGGER.log(Level.SEVERE, "Could not verify the account", e);
    }

    return Objects.requireNonNullElse(
        message, "The account could not be verified, please try again later");
  }
}

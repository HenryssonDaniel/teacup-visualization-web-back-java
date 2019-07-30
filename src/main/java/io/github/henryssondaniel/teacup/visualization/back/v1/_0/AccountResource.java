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
import java.util.Optional;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;

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

    return noUserRequired(httpServletRequest.getSession())
        .orElseGet(() -> changePassword(password, token))
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
  public static Response logIn(@Context HttpServletRequest httpServletRequest) {
    LOGGER.log(Level.FINE, "Log in");

    return noUserRequired(httpServletRequest.getSession()).orElseGet(Response::ok).build();
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

  private ResponseBuilder changePassword(String password, String token) {
    ResponseBuilder responseBuilder;

    try {
      responseBuilder =
          Response.status(
              changePasswordRequest(
                  getJwtVerifier().verify(token).getClaim("email").asString(), password));
    } catch (JWTVerificationException e) {
      LOGGER.log(Level.SEVERE, "The token could not be verified", e);
      responseBuilder = Response.status(FORBIDDEN);
    }

    return responseBuilder;
  }

  private static int changePasswordRequest(String email, String password) {
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

      if (statusCode == Status.OK.getStatusCode()) LOGGER.info("Log in");
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

  private static ResponseBuilder logOut(HttpSession httpSession) {
    httpSession.removeAttribute("id");

    return Response.ok();
  }

  private static Optional<ResponseBuilder> noUserRequired(HttpSession httpSession) {
    return Optional.ofNullable(
        null == httpSession.getAttribute("id") ? null : Response.status(Status.UNAUTHORIZED));
  }
}

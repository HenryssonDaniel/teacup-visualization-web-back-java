package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static io.github.henryssondaniel.teacup.visualization.back.v1._0.Utils.allowCredentials;
import static io.github.henryssondaniel.teacup.visualization.back.v1._0.Utils.userRequired;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.JWTVerifier;
import io.github.henryssondaniel.teacup.core.configuration.Factory;
import java.net.http.HttpClient;
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
  private static final String EMAIL = "email";
  private static final String ID = "id";
  private static final Logger LOGGER = Logger.getLogger(AccountResource.class.getName());
  private static final String LOG_IN = "logIn";
  private static final Properties PROPERTIES_CORE = Factory.getProperties();
  private static final String RECOVER = "recover";
  private static final String SECRET = "password";
  private static final String TOKEN = "token";

  private final Account account;
  private final Properties properties;

  private Algorithm algorithm;
  private JWTVerifier jwtVerifier;

  /**
   * Constructor.
   *
   * @since 1.0
   */
  public AccountResource() {
    this(PROPERTIES_CORE);
  }

  AccountResource(
      Account account, Algorithm algorithm, JWTVerifier jwtVerifier, Properties properties) {
    this.account = account;
    this.algorithm = algorithm;
    this.jwtVerifier = jwtVerifier;
    this.properties = new Properties(properties);
  }

  private AccountResource(Properties properties) {
    this(new AccountImpl(HttpClient.newHttpClient(), properties), null, null, properties);
  }

  /**
   * Authorized.
   *
   * @return the response
   * @since 1.0
   */
  @GET
  @Path(AUTHORIZED)
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
  public Response changePassword(String data, @Context HttpServletRequest httpServletRequest) {
    LOGGER.log(Level.FINE, "Change password");

    var httpSession = httpServletRequest.getSession();
    return allowCredentials(
        noUserRequired(httpSession)
            .orElseGet(
                () -> account.changePassword(httpSession, new JSONObject(data), getJwtVerifier())));
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
                      account.logIn(
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
            .orElseGet(
                () ->
                    Response.status(
                        account.recover(getAlgorithm(), new JSONObject(data).getString(EMAIL)))));
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
            .orElseGet(
                () ->
                    Response.status(
                        account.signUp(getAlgorithm(), httpServletRequest, new JSONObject(data)))));
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
      data = account.verify(getJwtVerifier().verify(token).getClaim(EMAIL).asString());
    } catch (JWTVerificationException e) {
      LOGGER.log(Level.SEVERE, "The token could not be verified", e);
      data = "The token is not valid";
    }

    return data;
  }

  private Algorithm getAlgorithm() {
    if (algorithm == null) algorithm = Algorithm.HMAC256(properties.getProperty("secret.key"));

    return algorithm;
  }

  private JWTVerifier getJwtVerifier() {
    if (jwtVerifier == null) jwtVerifier = JWT.require(getAlgorithm()).build();

    return jwtVerifier;
  }

  private static Optional<ResponseBuilder> noUserRequired(HttpSession httpSession) {
    return Optional.ofNullable(
        httpSession.getAttribute(ID) == null ? null : Response.status(Status.UNAUTHORIZED));
  }
}

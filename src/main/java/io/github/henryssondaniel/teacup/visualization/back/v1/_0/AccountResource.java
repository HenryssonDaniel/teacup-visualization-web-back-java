package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Account resource. Handles account related requests.
 *
 * @since 1.0
 */
@Path("{a:v1/account|v1.0/account|account}")
public class AccountResource {
  private static final Logger LOGGER = Logger.getLogger(AccountResource.class.getName());

  /**
   * Dashboard.
   *
   * @return the response
   * @since 1.0
   */
  @GET
  @Path("authorized")
  @Produces(MediaType.APPLICATION_JSON)
  public static Response authorized(@Context HttpServletRequest httpServletRequest) {
    LOGGER.log(Level.FINE, "Authorized");

    var httpSession = httpServletRequest.getSession();
    return Utils.userRequired(httpSession).orElseGet(Response::ok).build();
  }
}

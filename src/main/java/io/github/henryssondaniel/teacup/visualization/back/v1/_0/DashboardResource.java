package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static io.github.henryssondaniel.teacup.visualization.back.v1._0.Utils.allowCredentials;
import static io.github.henryssondaniel.teacup.visualization.back.v1._0.Utils.userRequired;

import io.github.henryssondaniel.teacup.core.configuration.Factory;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;
import org.json.JSONObject;

/**
 * Dashboard resource. Handles dashboard related requests.
 *
 * @since 1.0
 */
public class DashboardResource {
  private static final Logger LOGGER = Logger.getLogger(DashboardResource.class.getName());
  private static final Properties PROPERTIES = Factory.getProperties();

  /**
   * Dashboard.
   *
   * @return the response
   * @since 1.0
   */
  @GET
  @Path("{a:v1/dashboard|v1.0/dashboard|dashboard}")
  @Produces(MediaType.APPLICATION_JSON)
  public static Response dashboard(@Context HttpServletRequest httpServletRequest) {
    LOGGER.log(Level.FINE, "Dashboard");

    var httpSession = httpServletRequest.getSession();
    return allowCredentials(userRequired(httpSession).orElseGet(() -> getDashBoard(httpSession)));
  }

  private static ResponseBuilder getDashBoard(HttpSession httpSession) {
    var jsonObject =
        new JSONObject(
            "{\"account\": {\"firstName\": \""
                + httpSession.getAttribute("firstName")
                + "\", \"lastName\": \""
                + httpSession.getAttribute("lastName")
                + "}}");

    int statusCode;
    try {
      statusCode = getSessions(jsonObject);
    } catch (IOException | InterruptedException e) {
      LOGGER.log(Level.SEVERE, "Could not get sessions", e);
      statusCode = Status.INTERNAL_SERVER_ERROR.getStatusCode();
    }

    return Response.status(statusCode)
        .entity(jsonObject.toString())
        .type(MediaType.APPLICATION_JSON);
  }

  private static int getSessions(JSONObject jsonObject) throws IOException, InterruptedException {
    var httpResponse =
        HttpClient.newHttpClient()
            .send(
                HttpRequest.newBuilder()
                    .uri(
                        URI.create(
                            PROPERTIES.getProperty("service.report") + "/api/session/summary"))
                    .build(),
                BodyHandlers.ofString());

    var statusCode = httpResponse.statusCode();

    if (statusCode == Status.OK.getStatusCode())
      jsonObject.put("sessions", new JSONObject(httpResponse.body()).getJSONArray("sessions"));

    return statusCode;
  }
}

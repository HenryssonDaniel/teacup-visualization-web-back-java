package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;

enum Utils {
  ;

  private static final Logger LOGGER = Logger.getLogger(Utils.class.getName());

  static Response allowCredentials(ResponseBuilder responseBuilder) {
    return responseBuilder.header("Access-Control-Allow-credentials", "true").build();
  }

  static int handleException(String message, Throwable throwable) {
    LOGGER.log(Level.SEVERE, message, throwable);
    return Status.INTERNAL_SERVER_ERROR.getStatusCode();
  }

  static Optional<ResponseBuilder> userRequired(HttpSession httpSession) {
    return Optional.ofNullable(
        httpSession.getAttribute("id") == null ? Response.status(Status.UNAUTHORIZED) : null);
  }
}

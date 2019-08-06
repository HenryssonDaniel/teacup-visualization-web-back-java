package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import java.util.Optional;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;

enum Utils {
  ;

  static Response allowCredentials(ResponseBuilder responseBuilder) {
    return responseBuilder.header("Access-Control-Allow-credentials", "true").build();
  }

  static Optional<ResponseBuilder> userRequired(HttpSession httpSession) {
    return Optional.ofNullable(
        null == httpSession.getAttribute("id") ? Response.status(Status.UNAUTHORIZED) : null);
  }
}

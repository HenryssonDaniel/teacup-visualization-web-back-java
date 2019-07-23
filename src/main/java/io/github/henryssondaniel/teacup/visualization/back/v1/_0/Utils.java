package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import java.util.Optional;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;

enum Utils {
  ;

  static Optional<ResponseBuilder> userRequired(HttpSession httpSession) {
    return Optional.ofNullable(
        httpSession.getAttribute("id") == null ? Response.status(Status.UNAUTHORIZED) : null);
  }
}

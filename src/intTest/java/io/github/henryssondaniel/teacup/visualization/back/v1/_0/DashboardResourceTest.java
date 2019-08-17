package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response.Status;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class DashboardResourceTest {
  private final HttpServletRequest httpServletRequest = new TestHttpServletRequest();

  @Disabled("Needs report service and database connection")
  @Test
  void dashboard() {
    var httpSession = httpServletRequest.getSession();
    httpSession.setAttribute("firstName", "firstName");
    httpSession.setAttribute("id", "123");
    httpSession.setAttribute("lastName", "lastName");

    try (var response = new DashboardResource().dashboard(httpServletRequest)) {
      assertThat((String) response.getEntity())
          .containsPattern(
              Pattern.compile(
                  "\\{\"sessions\":\\[.*],\"account\":\\{\"firstName\":\"firstName\",\"lastName\":"
                      + "\"lastName\"}}"));
      assertThat(response.getMediaType()).isEqualTo(MediaType.APPLICATION_JSON_TYPE);
      assertThat(response.getStatus()).isEqualTo(Status.OK.getStatusCode());
    }
  }

  @Test
  void dashboardWhenUnauthorized() {
    try (var response = new DashboardResource().dashboard(httpServletRequest)) {
      assertThat(response.getEntity()).isNull();
      assertThat(response.getMediaType()).isNull();
      assertThat(response.getStatus()).isEqualTo(Status.UNAUTHORIZED.getStatusCode());
    }
  }
}

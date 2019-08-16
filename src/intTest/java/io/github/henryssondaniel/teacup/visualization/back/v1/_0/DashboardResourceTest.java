package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.regex.Pattern;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response.Status;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

@Disabled("Needs report service and database connection")
class DashboardResourceTest {
  @Test
  void dashboard() {
    try (var response = new DashboardResource().dashboard(new TestHttpServletRequest())) {
      assertThat((String) response.getEntity())
          .containsPattern(
              Pattern.compile(
                  "\\{\"sessions\":\\[.*],\"account\":\\{\"firstName\":\"\",\"lastName\":\"\"}}"));
      assertThat(response.getMediaType()).isEqualTo(MediaType.APPLICATION_JSON_TYPE);
      assertThat(response.getStatus()).isEqualTo(Status.OK.getStatusCode());
    }
  }
}

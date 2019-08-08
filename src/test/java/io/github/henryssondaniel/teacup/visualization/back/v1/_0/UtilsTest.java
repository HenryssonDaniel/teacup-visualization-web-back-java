package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.List;
import java.util.Map.Entry;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.junit.jupiter.api.Test;

class UtilsTest {
  private final HttpSession httpSession = mock(HttpSession.class);

  @Test
  void allowCredentials() {
    try (var response = Utils.allowCredentials(Response.ok())) {
      Iterable<Entry<String, List<Object>>> entrySet = response.getHeaders().entrySet();
      assertThat(entrySet).hasSize(1);

      var entry = entrySet.iterator().next();

      assertThat(entry.getKey()).isEqualTo("Access-Control-Allow-credentials");
      assertThat(entry.getValue()).containsExactly("true");
    }
  }

  @Test
  void handleException() {
    assertThat(Utils.handleException("message", new IOException("test")))
        .isEqualTo(Status.INTERNAL_SERVER_ERROR.getStatusCode());
  }

  @Test
  void userRequired() {
    when(httpSession.getAttribute("id")).thenReturn("123");
    assertThat(Utils.userRequired(httpSession)).isEmpty();
  }

  @Test
  void userRequiredWhenNoSessionId() {
    var optional = Utils.userRequired(httpSession);

    assertThat(optional).isNotEmpty();

    try (var response = optional.get().build()) {
      assertThat(response.getStatus()).isEqualTo(Status.UNAUTHORIZED.getStatusCode());
    }
  }
}

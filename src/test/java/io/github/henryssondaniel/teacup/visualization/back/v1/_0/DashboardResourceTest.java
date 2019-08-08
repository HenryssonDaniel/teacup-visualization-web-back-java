package io.github.henryssondaniel.teacup.visualization.back.v1._0;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.Response.StatusType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class DashboardResourceTest {
  private static final String ALLOW_CREDENTIALS = "Access-Control-Allow-credentials";
  private static final String ID = "id";
  private static final String MESSAGE = "test";
  private static final String TRUE = "true";

  private final HttpClient httpClient = mock(HttpClient.class);
  private final HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
  private final HttpSession httpSession = mock(HttpSession.class);

  @Mock private HttpResponse<String> httpResponse;

  @BeforeEach
  void beforeEach() throws IOException, InterruptedException {
    MockitoAnnotations.initMocks(this);

    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenReturn(httpResponse);
    when(httpServletRequest.getSession()).thenReturn(httpSession);
    when(httpSession.getAttribute(ID)).thenReturn("123");
  }

  @Test
  void dashboard() throws IOException, InterruptedException {
    when(httpResponse.body()).thenReturn("{\"sessions\": []}");
    when(httpResponse.statusCode()).thenReturn(Status.OK.getStatusCode());

    verifyDashboard(Status.OK);
    verifyMocks();
  }

  @Test
  void dashboardWhenInterruptedException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(new InterruptedException(MESSAGE));

    verifyDashboard(Status.INTERNAL_SERVER_ERROR);
    verifyMocks();
  }

  @Test
  void dashboardWhenIoException() throws IOException, InterruptedException {
    when(httpClient.send(any(HttpRequest.class), eq(BodyHandlers.ofString())))
        .thenThrow(new IOException(MESSAGE));

    verifyDashboard(Status.INTERNAL_SERVER_ERROR);
    verifyMocks();
  }

  @Test
  void dashboardWhenNotAuthorized() {
    when(httpSession.getAttribute(ID)).thenReturn(null);

    try (var response = new DashboardResource().dashboard(httpServletRequest)) {
      assertThat(response.getStatus()).isEqualTo(Status.UNAUTHORIZED.getStatusCode());

      Iterable<Entry<String, List<Object>>> entrySet = response.getHeaders().entrySet();

      assertThat(entrySet).hasSize(1);
      verifyKeyValue(entrySet.iterator(), ALLOW_CREDENTIALS, TRUE);
    }

    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);

    verify(httpSession).getAttribute(ID);
    verifyNoMoreInteractions(httpSession);
  }

  @Test
  void dashboardWhenResponseNotOk() throws IOException, InterruptedException {
    when(httpResponse.statusCode()).thenReturn(Status.FOUND.getStatusCode());

    verifyDashboard(Status.FOUND);
    verifyMocks();
  }

  private void verifyDashboard(StatusType statusType) {
    try (var response =
        new DashboardResource(httpClient, URI.create("http://localhost"))
            .dashboard(httpServletRequest)) {
      assertThat(response.getStatus()).isEqualTo(statusType.getStatusCode());

      Iterable<Entry<String, List<Object>>> entrySet = response.getHeaders().entrySet();
      assertThat(entrySet).hasSize(2);

      var iterator = entrySet.iterator();
      verifyKeyValue(iterator, "Content-Type", MediaType.APPLICATION_JSON_TYPE);
      verifyKeyValue(iterator, ALLOW_CREDENTIALS, TRUE);
    }
  }

  private static void verifyKeyValue(
      Iterator<? extends Entry<String, List<Object>>> iterator, String key, Object value) {
    var entry = iterator.next();

    assertThat(entry.getKey()).isEqualTo(key);
    assertThat(entry.getValue()).containsExactly(value);
  }

  private void verifyMocks() throws IOException, InterruptedException {
    verify(httpClient).send(any(HttpRequest.class), eq(BodyHandlers.ofString()));
    verifyNoMoreInteractions(httpClient);

    verify(httpServletRequest).getSession();
    verifyNoMoreInteractions(httpServletRequest);

    verify(httpSession).getAttribute("firstName");
    verify(httpSession).getAttribute(ID);
    verify(httpSession).getAttribute("lastName");
    verifyNoMoreInteractions(httpSession);
  }
}

package io.github.henryssondaniel.teacup.visualization.back;

import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;

/**
 * CORS filter.
 *
 * @since 1.0
 */
public class CorsFilter implements ContainerResponseFilter {
  private static final Logger LOGGER = Logger.getLogger(CorsFilter.class.getName());

  @Override
  public void filter(
      ContainerRequestContext containerRequestContext,
      ContainerResponseContext containerResponseContext) {
    LOGGER.log(Level.FINE, "Filter");

    containerResponseContext
        .getHeaders()
        .add("Access-Control-Allow-Origin", containerRequestContext.getHeaderString("Origin"));
  }
}

package io.github.henryssondaniel.teacup.visualization.back;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.net.URI;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.EntityTag;
import javax.ws.rs.core.Link;
import javax.ws.rs.core.Link.Builder;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.PathSegment;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.Response.StatusType;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import javax.ws.rs.core.Variant;
import org.glassfish.jersey.message.internal.OutboundJaxrsResponse;
import org.junit.jupiter.api.Test;

class CorsFilterTest {
  private static final String HEADER_STRING = "headerString";

  @Test
  void filter() {
    ContainerRequestContext containerRequestContext = new TestContainerRequestContext();
    ContainerResponseContext containerResponseContext = new TestContainerResponseContextImpl();

    new CorsFilter().filter(containerRequestContext, containerResponseContext);

    assertThat(((TestContainerResponseContext) containerRequestContext).getCount()).isOne();
    assertThat(((TestContainerResponseContext) containerResponseContext).getCount()).isOne();
  }

  @FunctionalInterface
  private interface TestContainerResponseContext {
    int getCount();
  }

  private static class TestBuilder implements Builder {
    private static final Logger LOGGER = Logger.getLogger(TestBuilder.class.getName());

    @Override
    public Builder baseUri(URI uri) {
      LOGGER.log(Level.FINE, "Base URI");
      return this;
    }

    @Override
    public Builder baseUri(String uri) {
      LOGGER.log(Level.FINE, "Base URI");
      return this;
    }

    @Override
    public Link build(Object... values) {
      LOGGER.log(Level.FINE, "Build");
      return Link.valueOf("link");
    }

    @Override
    public Link buildRelativized(URI uri, Object... values) {
      LOGGER.log(Level.FINE, "Build relativized");
      return Link.valueOf("link");
    }

    @Override
    public Builder link(Link link) {
      LOGGER.log(Level.FINE, "Link");
      return this;
    }

    @Override
    public Builder link(String link) {
      LOGGER.log(Level.FINE, "Link");
      return this;
    }

    @Override
    public Builder param(String name, String value) {
      LOGGER.log(Level.FINE, "Param");
      return this;
    }

    @Override
    public Builder rel(String rel) {
      LOGGER.log(Level.FINE, "Rel");
      return this;
    }

    @Override
    public Builder title(String title) {
      LOGGER.log(Level.FINE, "Title");
      return this;
    }

    @Override
    public Builder type(String type) {
      LOGGER.log(Level.FINE, "Type");
      return this;
    }

    @Override
    public Builder uri(URI uri) {
      LOGGER.log(Level.FINE, "URI");
      return this;
    }

    @Override
    public Builder uri(String uri) {
      LOGGER.log(Level.FINE, "URI");
      return this;
    }

    @Override
    public Builder uriBuilder(UriBuilder uriBuilder) {
      LOGGER.log(Level.FINE, "URI builder");
      return this;
    }
  }

  private static class TestContainerRequestContext
      implements ContainerRequestContext, TestContainerResponseContext {
    private static final Logger LOGGER =
        Logger.getLogger(TestContainerRequestContext.class.getName());

    private int count;
    private SecurityContext securityContext;

    @Override
    public void abortWith(Response response) {
      LOGGER.log(Level.FINE, "Abort with");
    }

    @Override
    public List<Locale> getAcceptableLanguages() {
      LOGGER.log(Level.FINE, "Get acceptable languages");
      return Collections.emptyList();
    }

    @Override
    public List<MediaType> getAcceptableMediaTypes() {
      LOGGER.log(Level.FINE, "Get acceptable media types");
      return Collections.emptyList();
    }

    @Override
    public Map<String, Cookie> getCookies() {
      LOGGER.log(Level.FINE, "Get cookies");
      return Collections.emptyMap();
    }

    @Override
    public int getCount() {
      return count;
    }

    @Override
    public Date getDate() {
      LOGGER.log(Level.FINE, "Get date");
      return Date.from(Instant.now());
    }

    @Override
    public InputStream getEntityStream() {
      LOGGER.log(Level.FINE, "Get entity stream");
      return InputStream.nullInputStream();
    }

    @Override
    public String getHeaderString(String name) {
      LOGGER.log(Level.FINE, "Get header string");
      count++;
      return HEADER_STRING;
    }

    @Override
    public MultivaluedMap<String, String> getHeaders() {
      LOGGER.log(Level.FINE, "Get headers");
      return new MultivaluedHashMap<>();
    }

    @Override
    public Locale getLanguage() {
      LOGGER.log(Level.FINE, "Get language");
      return Locale.getDefault();
    }

    @Override
    public int getLength() {
      LOGGER.log(Level.FINE, "Get length");
      return 0;
    }

    @Override
    public MediaType getMediaType() {
      LOGGER.log(Level.FINE, "Get media type");
      return MediaType.WILDCARD_TYPE;
    }

    @Override
    public String getMethod() {
      LOGGER.log(Level.FINE, "Get method");
      return "";
    }

    @Override
    public Object getProperty(String name) {
      LOGGER.log(Level.FINE, "Get property");
      return "";
    }

    @Override
    public Collection<String> getPropertyNames() {
      LOGGER.log(Level.FINE, "Get property names");
      return Collections.emptyList();
    }

    @Override
    public Request getRequest() {
      LOGGER.log(Level.FINE, "Get request");
      return new TestRequest();
    }

    @Override
    public SecurityContext getSecurityContext() {
      LOGGER.log(Level.FINE, "Get security context");
      return securityContext;
    }

    @Override
    public UriInfo getUriInfo() {
      LOGGER.log(Level.FINE, "Get URI info");
      return new TestUriInfo();
    }

    @Override
    public boolean hasEntity() {
      LOGGER.log(Level.FINE, "Has entity");
      return false;
    }

    @Override
    public void removeProperty(String name) {
      LOGGER.log(Level.FINE, "Remove property");
    }

    @Override
    public void setEntityStream(InputStream input) {
      LOGGER.log(Level.FINE, "Set entity stream");
    }

    @Override
    public void setMethod(String method) {
      LOGGER.log(Level.FINE, "Set method");
    }

    @Override
    public void setProperty(String name, Object object) {
      LOGGER.log(Level.FINE, "Set property");
    }

    @Override
    public void setRequestUri(URI requestUri) {
      LOGGER.log(Level.FINE, "Set request URI");
    }

    @Override
    public void setRequestUri(URI baseUri, URI requestUri) {
      LOGGER.log(Level.FINE, "Set request URI");
    }

    @Override
    public void setSecurityContext(SecurityContext context) {
      securityContext = context;
    }
  }

  private static class TestContainerResponseContextImpl
      implements ContainerResponseContext, TestContainerResponseContext {
    private static final Annotation[] ANNOTATIONS = new Annotation[0];
    private static final Logger LOGGER =
        Logger.getLogger(TestContainerResponseContextImpl.class.getName());

    private final MultivaluedMap<String, Object> multivaluedMap = new MultivaluedHashMap<>();
    private final MultivaluedMap<String, String> multivaluedMapString = new MultivaluedHashMap<>();
    private int count;

    @Override
    public Set<String> getAllowedMethods() {
      LOGGER.log(Level.FINE, "Get allowed methods");
      return Collections.emptySet();
    }

    @Override
    public Map<String, NewCookie> getCookies() {
      LOGGER.log(Level.FINE, "Get cookies");
      return Collections.emptyMap();
    }

    @Override
    public int getCount() {
      return count;
    }

    @Override
    public Date getDate() {
      LOGGER.log(Level.FINE, "Get date");
      return Date.from(Instant.now());
    }

    @Override
    public Object getEntity() {
      LOGGER.log(Level.FINE, "Get entity");
      return "";
    }

    @Override
    public Annotation[] getEntityAnnotations() {
      LOGGER.log(Level.FINE, "Get entity annotations");
      return ANNOTATIONS;
    }

    @Override
    public Class<?> getEntityClass() {
      LOGGER.log(Level.FINE, "Get entity class");
      return String.class;
    }

    @Override
    public OutputStream getEntityStream() {
      LOGGER.log(Level.FINE, "Get entity stream");
      return OutputStream.nullOutputStream();
    }

    @Override
    public EntityTag getEntityTag() {
      LOGGER.log(Level.FINE, "Get entity tag");
      return EntityTag.valueOf("value");
    }

    @Override
    public Type getEntityType() {
      LOGGER.log(Level.FINE, "Get entity type");
      return "".getClass();
    }

    @Override
    public String getHeaderString(String name) {
      LOGGER.log(Level.FINE, "Get header string");
      return multivaluedMapString.getFirst(name);
    }

    @Override
    public MultivaluedMap<String, Object> getHeaders() {
      LOGGER.log(Level.FINE, "Get headers");

      count++;

      return new MultivaluedHashMap<>(multivaluedMap);
    }

    @Override
    public Locale getLanguage() {
      LOGGER.log(Level.FINE, "Get language");
      return Locale.FRANCE;
    }

    @Override
    public Date getLastModified() {
      LOGGER.log(Level.FINE, "Get last modified");
      return Date.from(Instant.now());
    }

    @Override
    public int getLength() {
      LOGGER.log(Level.FINE, "Get length");
      return 0;
    }

    @Override
    public Link getLink(String relation) {
      LOGGER.log(Level.FINE, "Get links");
      return Link.valueOf("type");
    }

    @Override
    public Builder getLinkBuilder(String relation) {
      LOGGER.log(Level.FINE, "Get link builder");
      return new TestBuilder();
    }

    @Override
    public Set<Link> getLinks() {
      LOGGER.log(Level.FINE, "Get links");
      return Collections.emptySet();
    }

    @Override
    public URI getLocation() {
      LOGGER.log(Level.FINE, "Get allowed methods");
      return URI.create("");
    }

    @Override
    public MediaType getMediaType() {
      LOGGER.log(Level.FINE, "Get media type");
      return MediaType.WILDCARD_TYPE;
    }

    @Override
    public int getStatus() {
      LOGGER.log(Level.FINE, "Get status");
      return 0;
    }

    @Override
    public StatusType getStatusInfo() {
      LOGGER.log(Level.FINE, "Get status info");
      return Status.OK;
    }

    @Override
    public MultivaluedMap<String, String> getStringHeaders() {
      LOGGER.log(Level.FINE, "Get string headers");
      return (MultivaluedMap<String, String>) Collections.unmodifiableMap(multivaluedMapString);
    }

    @Override
    public boolean hasEntity() {
      LOGGER.log(Level.FINE, "Has entity");
      return false;
    }

    @Override
    public boolean hasLink(String relation) {
      LOGGER.log(Level.FINE, "Has link");
      return false;
    }

    @Override
    public void setEntity(Object entity) {
      LOGGER.log(Level.FINE, "Set entity");
    }

    @Override
    public void setEntity(Object entity, Annotation[] annotations, MediaType mediaType) {
      LOGGER.log(Level.FINE, "Set entity");
    }

    @Override
    public void setEntityStream(OutputStream outputStream) {
      LOGGER.log(Level.FINE, "Set entity stream");
    }

    @Override
    public void setStatus(int code) {
      LOGGER.log(Level.FINE, "Set status");
      multivaluedMapString.put("key", Collections.emptyList());
    }

    @Override
    public void setStatusInfo(StatusType statusInfo) {
      LOGGER.log(Level.FINE, "Set status info");
      multivaluedMap.put("key", Collections.emptyList());
    }
  }

  private static class TestRequest implements Request {
    private static final Logger LOGGER = Logger.getLogger(TestRequest.class.getName());

    @Override
    public ResponseBuilder evaluatePreconditions(EntityTag eTag) {
      LOGGER.log(Level.FINE, "Evaluate preconditions");
      return new OutboundJaxrsResponse.Builder(null);
    }

    @Override
    public ResponseBuilder evaluatePreconditions(Date lastModified) {
      LOGGER.log(Level.FINE, "Evaluate preconditions");
      return new OutboundJaxrsResponse.Builder(null);
    }

    @Override
    public ResponseBuilder evaluatePreconditions(Date lastModified, EntityTag eTag) {
      LOGGER.log(Level.FINE, "Evaluate preconditions");
      return new OutboundJaxrsResponse.Builder(null);
    }

    @Override
    public ResponseBuilder evaluatePreconditions() {
      LOGGER.log(Level.FINE, "Evaluate preconditions");
      return new OutboundJaxrsResponse.Builder(null);
    }

    @Override
    public String getMethod() {
      LOGGER.log(Level.FINE, "Get method");
      return "";
    }

    @Override
    public Variant selectVariant(List<Variant> variants) {
      LOGGER.log(Level.FINE, "Select variant");
      return variants.get(0);
    }
  }

  private static class TestUriInfo implements UriInfo {
    private static final Logger LOGGER = Logger.getLogger(TestUriInfo.class.getName());

    @Override
    public URI getAbsolutePath() {
      LOGGER.log(Level.FINE, "Get absolute path");
      return URI.create("localhost");
    }

    @Override
    public UriBuilder getAbsolutePathBuilder() {
      LOGGER.log(Level.FINE, "Get absolute path builder");
      return UriBuilder.fromPath("localhost");
    }

    @Override
    public URI getBaseUri() {
      LOGGER.log(Level.FINE, "Get base URI");
      return URI.create("localhost");
    }

    @Override
    public UriBuilder getBaseUriBuilder() {
      LOGGER.log(Level.FINE, "Get base URI builder");
      return UriBuilder.fromPath("localhost");
    }

    @Override
    public List<Object> getMatchedResources() {
      LOGGER.log(Level.FINE, "Get matched resources");
      return Collections.emptyList();
    }

    @Override
    public List<String> getMatchedURIs() {
      LOGGER.log(Level.FINE, "Get matched URI's");
      return Collections.emptyList();
    }

    @Override
    public List<String> getMatchedURIs(boolean decode) {
      LOGGER.log(Level.FINE, "Get matched URI's");
      return Collections.emptyList();
    }

    @Override
    public String getPath() {
      LOGGER.log(Level.FINE, "Get path");
      return "";
    }

    @Override
    public String getPath(boolean decode) {
      LOGGER.log(Level.FINE, "Get path");
      return "";
    }

    @Override
    public MultivaluedMap<String, String> getPathParameters() {
      LOGGER.log(Level.FINE, "Get path parameters");
      return new MultivaluedHashMap<>();
    }

    @Override
    public MultivaluedMap<String, String> getPathParameters(boolean decode) {
      LOGGER.log(Level.FINE, "Get path parameters");
      return new MultivaluedHashMap<>();
    }

    @Override
    public List<PathSegment> getPathSegments() {
      LOGGER.log(Level.FINE, "Get path segments");
      return Collections.emptyList();
    }

    @Override
    public List<PathSegment> getPathSegments(boolean decode) {
      LOGGER.log(Level.FINE, "Get path segments");
      return Collections.emptyList();
    }

    @Override
    public MultivaluedMap<String, String> getQueryParameters() {
      LOGGER.log(Level.FINE, "Get query parameters");
      return new MultivaluedHashMap<>();
    }

    @Override
    public MultivaluedMap<String, String> getQueryParameters(boolean decode) {
      LOGGER.log(Level.FINE, "Get query parameters");
      return new MultivaluedHashMap<>();
    }

    @Override
    public URI getRequestUri() {
      LOGGER.log(Level.FINE, "Get request URI");
      return URI.create("localhost");
    }

    @Override
    public UriBuilder getRequestUriBuilder() {
      LOGGER.log(Level.FINE, "Get request URI builder");
      return UriBuilder.fromPath("localhost");
    }

    @Override
    public URI relativize(URI uri) {
      LOGGER.log(Level.FINE, "Relativize");
      return uri;
    }

    @Override
    public URI resolve(URI uri) {
      LOGGER.log(Level.FINE, "Resolve");
      return uri;
    }
  }
}

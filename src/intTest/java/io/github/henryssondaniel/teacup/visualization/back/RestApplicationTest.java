package io.github.henryssondaniel.teacup.visualization.back;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.henryssondaniel.teacup.visualization.back.v1._0.AccountResource;
import io.github.henryssondaniel.teacup.visualization.back.v1._0.DashboardResource;
import org.junit.jupiter.api.Test;

class RestApplicationTest {
  @Test
  void getClasses() {
    assertThat(new RestApplication().getClasses())
        .containsExactlyInAnyOrder(
            AccountResource.class, CorsFilter.class, DashboardResource.class);
  }
}

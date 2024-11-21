package com.example.demo_authen_jwt.configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfiguration {

  @Bean
  public OpenAPI customizeOpenAPI() {
    final String jwtSecuritySchemeName = "bearerAuth";

    return new OpenAPI()
          .info(new Info().title("My API").version("v1"))
          .addSecurityItem(new SecurityRequirement().addList(jwtSecuritySchemeName))
          .components(new Components()
                .addSecuritySchemes(jwtSecuritySchemeName,
                      new SecurityScheme()
                            .type(SecurityScheme.Type.HTTP)
                            .scheme("bearer")
                            .bearerFormat("JWT")
                            .description("JWT Authentication")
                )
          );
  }
}

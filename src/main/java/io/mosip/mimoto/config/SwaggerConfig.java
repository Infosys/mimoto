package io.mosip.mimoto.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    private static final Logger logger = LoggerFactory.getLogger(SwaggerConfig.class);

    @Autowired
    private OpenApiProperties openApiProperties;

    @Bean
    public OpenAPI openApi() {
        OpenAPI api = new OpenAPI()
                .components(new Components())
                .info(new Info()
                        .title(openApiProperties.getInfo().getTitle())
                        .version(openApiProperties.getInfo().getVersion())
                        .description(openApiProperties.getInfo().getDescription())
                        .license(new License()
                                .name(openApiProperties.getInfo().getLicense().getName())
                                .url(openApiProperties.getInfo().getLicense().getUrl())));

        openApiProperties.getService().getServers().forEach(server -> {
            api.addServersItem(new Server().description(server.getDescription()).url(server.getUrl()));
        });
        logger.info("swagger open api bean is ready");
        return api;
    }

    @Bean
    public GroupedOpenApi groupedOpenApi() {
        return GroupedOpenApi.builder().group(openApiProperties.getGroup().getName())
                .pathsToMatch(openApiProperties.getGroup().getPaths().stream().toArray(String[]::new))
                .build();
    }

}

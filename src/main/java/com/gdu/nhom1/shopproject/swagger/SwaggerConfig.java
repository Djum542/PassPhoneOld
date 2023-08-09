package com.gdu.nhom1.shopproject.swagger;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@Configuration
@EnableSwagger2
public class SwaggerConfig {
    @Bean
    public Docket postApi(){
        return  new Docket(DocumentationType.SWAGGER_2).groupName("public_api")
                .apiInfo(apiInfo())
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.gdu.nhom1.shopproject.controllers"))
                .build();
    }
    private ApiInfo apiInfo(){
        return new ApiInfoBuilder().title("SHOP ELECTROLIC")
                .description("Shop electrolic ")
                .termsOfServiceUrl("https://electricfilt.com")
                .licenseUrl("shopelectric@gmail.com").version("1.0").build();
    }
}

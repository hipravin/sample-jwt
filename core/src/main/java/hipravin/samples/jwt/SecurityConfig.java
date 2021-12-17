package hipravin.samples.jwt;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Configuration
    @Order(SecurityProperties.BASIC_AUTH_ORDER - 90)
    public static class PublicApiConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/api/v1/public/**")
                    .authorizeRequests().anyRequest().permitAll();
        }
    }

    @Configuration
    @Order(SecurityProperties.BASIC_AUTH_ORDER - 100)
    public static class ApiSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.antMatcher("/api/v1/secure/**")
                    .csrf().disable()
                    .authorizeRequests()
                    .antMatchers("/api/v1/secure/admin/**").hasRole("ADMIN")
                    .anyRequest().authenticated()
                    .and().exceptionHandling()
                        .authenticationEntryPoint((httpServletRequest, httpServletResponse, e) -> httpServletResponse.setStatus(417))
                    .and().exceptionHandling()
                        .accessDeniedHandler((httpServletRequest, httpServletResponse, e) -> httpServletResponse.setStatus(417))//just for better visibility
                    .and().addFilterBefore(new JWTAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        }
    }
}

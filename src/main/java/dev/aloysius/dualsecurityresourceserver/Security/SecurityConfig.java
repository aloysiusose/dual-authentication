package dev.aloysius.dualsecurityresourceserver.Security;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return  new BCryptPasswordEncoder();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain basicSecurityFIlterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf(AbstractHttpConfigurer::disable);

        httpSecurity.securityMatcher("/api/v1/home/**")
                .authorizeHttpRequests(auth ->{
                    auth.requestMatchers(new MvcRequestMatcher(new HandlerMappingIntrospector(), "/api/v1/home/welcome")).authenticated();
                });
        httpSecurity.httpBasic(Customizer.withDefaults());
        return httpSecurity.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain daulSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        httpSecurity.securityMatcher("/api/v1/auth/**")
                        .authorizeHttpRequests(auth ->{
                           auth.requestMatchers(new MvcRequestMatcher(new HandlerMappingIntrospector(), "/api/v1/auth/register"),
                                   new MvcRequestMatcher(new HandlerMappingIntrospector(), "//api/v1/auth/authenticate")).permitAll();
                           auth.anyRequest().authenticated();
                        });

        httpSecurity.httpBasic(Customizer.withDefaults())
                .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()));
        return httpSecurity.build();
    }

    @Bean
    public KeyPair keyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        kg.initialize(2048);
        return kg.generateKeyPair();
    }

    @Bean
    public JwtEncoder jwtEncoder() throws NoSuchAlgorithmException {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair().getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair().getPrivate();

        JWK jwk = new RSAKey.Builder(publicKey).privateKey(privateKey).build();

        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);

    }
    @Bean
    public JwtDecoder jwtDecoder() throws NoSuchAlgorithmException {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair().getPublic();
        return NimbusJwtDecoder.withPublicKey(publicKey).build();

    }
}

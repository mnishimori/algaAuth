package com.algaworks.algafoodauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                    .withClient("algafood-web")
                    .secret(passwordEncoder.encode("web123"))
                    .authorizedGrantTypes("password", "refresh_token")
                    .scopes("read", "write")
                    .accessTokenValiditySeconds(60 * 60 * 6) // o tempo padrão são 12 horas
                    .refreshTokenValiditySeconds(60 * 24 * 60 * 60) // 60 dias

                .and()
                    .withClient("algafood-analytics")
                    .secret(passwordEncoder.encode("analytics123"))
                    .authorizedGrantTypes("authorization_code")
                    .scopes("read", "write")
                    .redirectUris("http://aplicacao-cliente")

                .and()
                    .withClient("faturamento-app")
                    .secret(passwordEncoder.encode("faturamento123"))
                    .authorizedGrantTypes("client_credentials")
                    .scopes("read", "write")

                .and()
                    .withClient("checktoken")
                    .secret(passwordEncoder.encode("check123"));
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .authenticationManager(this.authenticationManager)
                .userDetailsService(this.userDetailsService);
    }
}

/**
 * FileName: AuthorizationServerConfig
 * Author:   linwd
 * Date:     2021/3/31 12:01
 * Description: 授权服务器配置
 * History:
 * <author>          <time>          <version>          <desc>
 * 作者姓名           修改时间           版本号              描述
 */
package com.yangxf.demoOauth2.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

/**
 * 〈一句话功能简述〉<br>
 * 〈授权服务器配置〉
 *
 * @author linwd
 * @create 2021/3/31
 * @since 1.0.0
 */
@Configuration
//开启授权服务
@EnableAuthorizationServer
public class OAuth2Config extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

    private static final String CLIENT_ID = "120001";
    private static final String SECRET_CHAR_SEQUENCE = "e1123123ew21312312";
    private static final String SCOPE_READ = "read";
    private static final String SCOPE_WRITE = "write";
    private static final String TRUST = "trust";
    private static final String USER ="user";
    private static final String ALL = "all";
    private static final int ACCESS_TOKEN_VALIDITY_SECONDS = 10*60;
    private static final int FREFRESH_TOKEN_VALIDITY_SECONDS = 10*60;
    // 密码模式授权模式
    private static final String GRANT_TYPE_PASSWORD = "password";
    //授权码模式
    private static final String AUTHORIZATION_CODE = "authorization_code";
    //refresh token模式
    private static final String REFRESH_TOKEN = "refresh_token";
    //简化授权模式
    private static final String IMPLICIT = "implicit";
    //指定哪些资源是需要授权验证的
    private static final String RESOURCE_ID = "resource_id";

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                // 使用内存存储
                .inMemory()
                //标记客户端id
                .withClient(CLIENT_ID)
                //客户端安全码
                .secret(passwordEncoder().encode(SECRET_CHAR_SEQUENCE))
                //为true 直接自动授权成功返回code
                .autoApprove(true)
                .redirectUris("http://127.0.0.1:8080/login") //重定向uri
                //允许授权范围
                .scopes(ALL)
                //token 时间秒
                .accessTokenValiditySeconds(ACCESS_TOKEN_VALIDITY_SECONDS)
                //刷新token 时间 秒
                .refreshTokenValiditySeconds(FREFRESH_TOKEN_VALIDITY_SECONDS)
                //允许授权类型
                .authorizedGrantTypes(AUTHORIZATION_CODE );
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // 使用内存保存生成的token
        endpoints.authenticationManager(authenticationManager).tokenStore(memoryTokenStore());
    }

    /**
     * 认证服务器的安全配置
     *
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                //.realm(RESOURCE_ID)
                // 开启/oauth/token_key验证端口认证权限访问
                .tokenKeyAccess("isAuthenticated()")
                //  开启/oauth/check_token验证端口认证权限访问
                .checkTokenAccess("isAuthenticated()")
                //允许表单认证
                .allowFormAuthenticationForClients();
    }

    @Bean
    public TokenStore memoryTokenStore() {
        // 最基本的InMemoryTokenStore生成token
        return new InMemoryTokenStore();
    }

}


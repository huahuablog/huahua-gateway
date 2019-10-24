package com.delta.mes.gateway.filter;

import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.StringUtils;
/**
 * 過濾器工廠 驗證token
 *
 * @author YONGHUI.ZHI
 *
 */
public class AuthorizeGatewayFilterFactory extends AbstractGatewayFilterFactory<AuthorizeGatewayFilterFactory.Config> {

    private static final Logger log = LoggerFactory.getLogger(AuthorizeGatewayFilterFactory.class);
    private static final String AUTHORIZE_TOKEN = "token" ;
    private static final String KEY = "valid";

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList(KEY,AUTHORIZE_TOKEN);
    }

    public AuthorizeGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
    	
    	if(config.valid)
        return (exchange, chain) -> {
        	
        	ServerHttpRequest request = exchange.getRequest();
        	HttpHeaders headers = request.getHeaders();
        	String token = headers.getFirst(AUTHORIZE_TOKEN);
        	log.info("URI:{},Token:{},call this API.",
        			request.getURI().getPath(), token);
            if (token == null) {
                token = request.getQueryParams().getFirst(AUTHORIZE_TOKEN);
            }
            ServerHttpResponse response = exchange.getResponse();
            if (StringUtils.isEmpty(token)) {
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }
            String authToken = config.token;
            if (authToken == null || !authToken.equals(token)) {
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }
            return chain.filter(exchange);
        };
        else {
        	 return (exchange, chain) -> {return chain.filter(exchange);};
        }
    }


    public static class Config {

        private boolean valid;
        
        private String token;

        public String getToken() {
			return token;
		}

		public void setToken(String token) {
			this.token = token;
		}

		public boolean isValid() {
            return valid;
        }

        public void setValid(boolean valid) {
            this.valid = valid;
        }

    }
}

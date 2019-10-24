package com.delta.mes.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
//import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;

import com.delta.mes.gateway.filter.AuthorizeGatewayFilterFactory;
import com.delta.mes.gateway.filter.ElapsedGatewayFilterFactory;
import com.delta.mes.gateway.globalfilter.AuthorizeGatewayGlobalFilter;
import com.delta.mes.gateway.predicate.TruePredicate;

//@EnableDiscoveryClient
@SpringBootApplication
public class GatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}
	
	@Bean
	public ElapsedGatewayFilterFactory elapsedGatewayFilterFactory() {
		return new ElapsedGatewayFilterFactory();
	}
	@Bean
	public TruePredicate truePredicate() {
		return new TruePredicate();
	}

	@Bean
	public AuthorizeGatewayFilterFactory authorizeGatewayFilterFactory() {
		return new AuthorizeGatewayFilterFactory();
	}

	@Bean
	@Order(-1)
	public GlobalFilter a() {
		return new AuthorizeGatewayGlobalFilter();
	}

}

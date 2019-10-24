package com.delta.mes.gateway.route;

import static java.util.Collections.synchronizedMap;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.cloud.gateway.route.RouteDefinitionRepository;
import org.springframework.cloud.gateway.support.NotFoundException;
import org.springframework.stereotype.Component;
import com.delta.mes.gateway.service.DynamicRouteServiceImpl;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * 自定義路由定義定位器
 * @author YONGHUI.ZHI
 *
 */
@Component
public class DBRouteDefinitionRepository  implements RouteDefinitionRepository {
	//保存路由
	private final Map<String, RouteDefinition> routes = synchronizedMap(new LinkedHashMap<String, RouteDefinition>());
	
	private Logger log = LoggerFactory.getLogger(DBRouteDefinitionRepository.class);
	//初始標準
	private boolean init_flag = true;
	//
	private DynamicRouteServiceImpl service;
	
	DBRouteDefinitionRepository(){
		this.service = new DynamicRouteServiceImpl();
	}
	
	@Override
	public Flux<RouteDefinition> getRouteDefinitions() {
		if(init_flag) {
			List<RouteDefinition> routeDefinitions = new ArrayList<>();
			try {
				routeDefinitions = service.quertAllRoutes();
				routes.clear();
				routeDefinitions.forEach(x->routes.put(x.getId(), x));
				init_flag=false;
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				log.error("Init Route Fail,Can't get Routes.",e);
			}
	        return Flux.fromIterable(routeDefinitions);
		}else {
			return Flux.fromIterable(routes.values());
		}
		
	}

	@Override
	public Mono<Void> delete(Mono<String> routeId) {
		return routeId.flatMap(id -> {
			if (routes.containsKey(id)) {
				routes.remove(id);
				return Mono.empty();
			}
			return Mono.defer(() -> Mono.error(new NotFoundException("RouteDefinition not found: "+routeId)));
		});
	}

	@Override
	public Mono<Void> save(Mono<RouteDefinition> route) {
		return route.flatMap( r -> {
			routes.put(r.getId(), r);
			return Mono.empty();
		});
	}

}

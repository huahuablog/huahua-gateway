package com.delta.mes.gateway.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.event.RefreshRoutesEvent;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.cloud.gateway.route.RouteDefinitionRepository;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Service;
import com.alibaba.fastjson.JSON;
import com.delta.mes.function.dao.BaseDao;
import com.delta.mes.function.service.BaseServices;
import com.delta.mes.gateway.entity.RouteEntity;

import reactor.core.publisher.Mono;

/**
 * 路由service
 * @author YONGHUI.ZHI
 *
 */
@Service
public class DynamicRouteServiceImpl extends BaseServices<BaseDao> implements ApplicationEventPublisherAware {

	public DynamicRouteServiceImpl() {
		super(LoggerFactory.getLogger(DynamicRouteServiceImpl.class));
	}

	@Autowired
	private RouteDefinitionRepository routeDefinitionRepository;

	private ApplicationEventPublisher publisher;
	
	/**
	 * 初始化路由
	 * @return
	 */
	public String init() {
		String failRoute = "";
		try {
			this.clear();
			List<RouteDefinition>routeDefinitions = this.quertAllRoutes();
			for (RouteDefinition r:routeDefinitions) {
				if(!this.add(r).equals("success")) {
					log.error("add route fail ,route:{}",r.toString());
					this.delete(r.getId());
					failRoute +=r.toString()+",";
					continue;
				}
			}
			//routeDefinitions.forEach(this::add);
			if (!failRoute.equals("")) {
				return "success,but add " + failRoute +"fail"; 
			}
			return "success";
		}catch(Exception e) {
			return "fail";
		}
		
	}
	
	/**
	 * 清空路由
	 * @return
	 */
	public String clear() {
		try {
			Map<String, RouteDefinition> routes = Collections.synchronizedMap(new LinkedHashMap<>());
			this.routeDefinitionRepository.getRouteDefinitions()
			.subscribe(x->routes.put(x.getId(), x));
			routes.forEach((x,y)->this.delete(x));
			return "success";
		}catch(Exception e) {
			e.printStackTrace();
			return "fail";
		}
		
	}

	/**
	 * 增加路由
	 * 
	 * @param definition
	 * @return
	 */
	public String add(RouteDefinition definition) {
		routeDefinitionRepository.save(Mono.just(definition)).subscribe();
		//發佈信息，更新路由配置
		try {
			this.publisher.publishEvent(new RefreshRoutesEvent(this));
			return "success";
		}catch(Exception e) {
			routeDefinitionRepository.delete(Mono.just(definition.getId())).subscribe();
			this.publisher.publishEvent(new RefreshRoutesEvent(this));
			log.error("add route fail,route:{}",definition.toString(),e);
			return "fail";
		}
		
		
	}

	/**
	 * 更新路由
	 * 
	 * @param definition
	 * @return
	 */
	public String update(RouteDefinition definition) {
		try {
			this.routeDefinitionRepository.delete(Mono.just(definition.getId())).subscribe();
		} catch (Exception e) {
			return "update fail,not find route  routeId: " + definition.getId();
		}
		try {
			routeDefinitionRepository.save(Mono.just(definition)).subscribe();
			//發佈信息，更新路由配置
			this.publisher.publishEvent(new RefreshRoutesEvent(this));
			return "success";
		} catch (Exception e) {
			return "update route  fail";
		}

	}

	/**
	 * 删除路由
	 * 
	 * @param id
	 * @return
	 */
	public String delete(String id) {
		try {
			this.routeDefinitionRepository.delete(Mono.just(id)).subscribe();
			//發佈信息，更新路由配置
			this.publisher.publishEvent(new RefreshRoutesEvent(this));
			return "delete success";
		} catch (Exception e) {
			e.printStackTrace();
			return "delete fail";
		}

	}
	
	/**
	 * 獲取內存中的某一個Route
	 * @param id
	 * @return
	 */
	public String getRoute(String id) {
		Map<String, RouteDefinition> routes = Collections.synchronizedMap(new LinkedHashMap<>());
		this.routeDefinitionRepository.getRouteDefinitions().filter(x -> x.getId().equals(id))
		.subscribe(x->{routes.put(x.getId(), x);});
		return JSON.toJSONString(routes);
	}
	
	/**
	 * 獲取內存中所有的Route
	 * @return
	 */
	public String getAllRoutes() {
		Map<String, RouteDefinition> routes = Collections.synchronizedMap(new LinkedHashMap<>());
		this.routeDefinitionRepository.getRouteDefinitions().subscribe(x->{
			routes.put(x.getId(), x);}
		);
		return JSON.toJSONString(routes);
	}
	
	
	/**
	 * 獲取數據庫中的Route定義
	 * @return
	 * @throws Exception
	 */
	public List<RouteDefinition> quertAllRoutes() throws Exception {
		String sql = "select id ,uri,route_order,predicates,filters from c_mes_api_route_t where valid = 1";
		List<RouteEntity> routeBeans = this.query("", sql, RouteEntity.class, new Object[] {});
		List<RouteDefinition> rList = new ArrayList<RouteDefinition>();
		
		for (RouteEntity r :routeBeans) {
			try {
				rList.add(r.toRouteDefinition());
			}catch(Exception e) {
				log.error("To RouteDefinition fail ,route:{}",r.toString(),e);
				continue;
			}
		}
		return rList;
		
	}
	
	/**
	 * 從DB中獲取一個route定義
	 * @param id
	 * @return
	 * @throws Exception
	 */
	public RouteDefinition quertRoute(String id) throws Exception {
		String sql = "select id ,uri,route_order,predicates,filters from c_mes_api_route_t where valid = 1 and id = ?";
		List<RouteEntity> routeBeans = this.query("", sql, RouteEntity.class, new Object[] { id });
		//List<RouteDefinition> rList = new ArrayList<RouteDefinition>();
		//routeBeans.forEach(x->rList.add(x.toRouteDefinition()));
		return routeBeans.get(0).toRouteDefinition();
	}
	
	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.publisher = applicationEventPublisher;
	}

}

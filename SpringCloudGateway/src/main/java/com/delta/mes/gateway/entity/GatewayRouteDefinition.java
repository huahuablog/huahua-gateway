package com.delta.mes.gateway.entity;

import java.util.ArrayList;
import java.util.List;

/**
 * 自定義網關路由
 * @author YONGHUI.ZHI
 *
 */
public class GatewayRouteDefinition {
	
	//路由ID
	private String id;
	
	//路由斷言集合配置
	private List<GatewayPredicateDefinition> predicates = new ArrayList<>();
	
	//路由過濾器集合配置
	private List<GatewayFilterDefinition> filters = new ArrayList<>();
	
	//路由規則轉發目標
	private String uri;
	
	//路由執行的順序
	private int order = 0;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public List<GatewayPredicateDefinition> getPredicates() {
		return predicates;
	}

	public void setPredicates(List<GatewayPredicateDefinition> predicates) {
		this.predicates = predicates;
	}

	public List<GatewayFilterDefinition> getFilters() {
		return filters;
	}

	public void setFilters(List<GatewayFilterDefinition> filters) {
		this.filters = filters;
	}

	public String getUri() {
		return uri;
	}

	public void setUri(String uri) {
		this.uri = uri;
	}

	public int getOrder() {
		return order;
	}

	public void setOrder(int order) {
		this.order = order;
	}
	
	
}

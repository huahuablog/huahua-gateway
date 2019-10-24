package com.delta.mes.gateway.entity;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Filter 規則
 * @author YONGHUI.ZHI
 *
 */
public class GatewayFilterDefinition {
	
	//Filter Name
	private String name;
	
	//對應路由規則
	private Map<String,String> args = new LinkedHashMap<>();

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Map<String, String> getArgs() {
		return args;
	}

	public void setArgs(Map<String, String> args) {
		this.args = args;
	}
	
	
}

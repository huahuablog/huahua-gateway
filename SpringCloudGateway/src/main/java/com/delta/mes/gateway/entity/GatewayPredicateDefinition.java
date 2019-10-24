package com.delta.mes.gateway.entity;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 斷言規則
 * @author YONGHUI.ZHI
 *
 */
public class GatewayPredicateDefinition {
	
	//斷言對應的Name
	private String name;
	//配置的斷言規則
	private Map<String ,String > args = new LinkedHashMap<>();

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

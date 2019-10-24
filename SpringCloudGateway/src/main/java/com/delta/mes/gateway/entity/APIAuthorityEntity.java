package com.delta.mes.gateway.entity;


import com.delta.mes.annotation.DataBaseColumnSetting;

public class APIAuthorityEntity {
	@DataBaseColumnSetting(columnName="api_path_name")
	private String apiPath;

	@DataBaseColumnSetting(columnName="auth_validate_flag")
	private String validFlag;

	@DataBaseColumnSetting(columnName="request_method")
	private String reqMethod;
	
	@DataBaseColumnSetting(columnName="controller")
	private String controllerName;
	
	@DataBaseColumnSetting(columnName="interval")
	private Integer interval;

	public String getApiPath() {
		return apiPath;
	}

	public void setApiPath(String apiPath) {
		this.apiPath = apiPath;
	}

	public String getValidFlag() {
		return validFlag;
	}

	public void setValidFlag(String validFlag) {
		this.validFlag = validFlag;
	}

	public String getReqMethod() {
		return reqMethod;
	}

	public void setReqMethod(String reqMethod) {
		this.reqMethod = reqMethod;
	}

	public String getControllerName() {
		return controllerName;
	}

	public void setControllerName(String controllerName) {
		this.controllerName = controllerName;
	}

	public Integer getInterval() {
		return interval;
	}

	public void setInterval(Integer interval) {
		this.interval = interval;
	}
	
	
}

package com.delta.mes.gateway.entity;

import java.net.URI;
import java.util.Date;

import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.handler.predicate.PredicateDefinition;
import org.springframework.cloud.gateway.route.RouteDefinition;
import com.delta.mes.annotation.DataBaseColumnSetting;
import com.delta.mes.util.JsonUtil;

/**
 * 路由數據庫實體
 * @author YONGHUI.ZHI
 *
 */
public class RouteEntity {
	@DataBaseColumnSetting(columnName="id")
	private String id;
	@DataBaseColumnSetting(columnName="uri")
	private String uri;
	@DataBaseColumnSetting(columnName="route_order")
	private int order;
	@DataBaseColumnSetting(columnName="predicates")
	private String predicates;
	@DataBaseColumnSetting(columnName="filters")
	private String filters;
	@DataBaseColumnSetting(columnName="create_time")
	private Date crateTime;
	@DataBaseColumnSetting(columnName="update_time")
	private Date updateTime;
	@DataBaseColumnSetting(columnName="valid")
	private String valid;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
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

	public String getPredicates() {
		return predicates;
	}

	public void setPredicates(String predicates) {
		this.predicates = predicates;
	}

	public String getFilters() {
		return filters;
	}

	public void setFilters(String filters) {
		this.filters = filters;
	}

	public Date getCrateTime() {
		return crateTime;
	}

	public void setCrateTime(Date crateTime) {
		this.crateTime = crateTime;
	}

	public Date getUpdateTime() {
		return updateTime;
	}

	public void setUpdateTime(Date updateTime) {
		this.updateTime = updateTime;
	}

	public String getValid() {
		return valid;
	}

	public void setValid(String valid) {
		this.valid = valid;
	}
	
	
	public RouteDefinition toRouteDefinition() {
		RouteDefinition rd = new RouteDefinition();
		rd.setId(this.id);
		rd.setOrder(this.order);
		//rd.setUri(UriComponentsBuilder.fromHttpUrl(this.uri).build().toUri());
		rd.setUri(URI.create(this.uri));
		rd.setFilters(JsonUtil.getArrayListFromJsonString(this.filters, FilterDefinition.class));
		rd.setPredicates(JsonUtil.getArrayListFromJsonString(this.predicates, PredicateDefinition.class));
		return rd;
	}

	@Override
	public String toString() {
		return "RouteEntity [id=" + id + ", uri=" + uri + ", order=" + order + ", predicates=" + predicates
				+ ", filters=" + filters + ", crateTime=" + crateTime + ", updateTime=" + updateTime + ", valid="
				+ valid + "]";
	}
	
	
}

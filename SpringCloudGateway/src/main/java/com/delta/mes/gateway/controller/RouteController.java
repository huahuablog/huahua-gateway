package com.delta.mes.gateway.controller;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.endpoint.web.annotation.RestControllerEndpoint;
import org.springframework.cloud.gateway.handler.predicate.PredicateDefinition;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.util.UriComponentsBuilder;

import com.delta.mes.gateway.entity.GatewayPredicateDefinition;
import com.delta.mes.gateway.entity.GatewayRouteDefinition;
import com.delta.mes.gateway.service.DynamicRouteServiceImpl;

@Configuration
@RestControllerEndpoint(id = "route")
public class RouteController {
	
	 	@Autowired
	    private DynamicRouteServiceImpl dynamicRouteService;
	 	
	 	/**
	 	 * 處理路由列表
	 	 * @return
	 	 */
	 	@GetMapping("/init")
	 	public String init() {
	 		return this.dynamicRouteService.init();
	 	}
	 	
	 	/**
	 	 * 清空路由列表
	 	 * @return
	 	 */

	 	@DeleteMapping("/clear")
	 	public String clear() {
	 		return this.dynamicRouteService.clear();
	 	}
	 	
	    /**
	     * 獲取路由信息
	     * @param id
	     * @return
	     */

	 	@GetMapping("/getRoute/{id}")
	    public String get(@PathVariable String id) {
	    	return this.dynamicRouteService.getRoute(id);
	    }
	    
	    /**
	     * 獲取路由列表
	     * @return
	     */

	    @GetMapping("/getAllRoutes")
	    public String getAll() {
	    	return this.dynamicRouteService.getAllRoutes();
	    }

	    /**
	     * 增加路由
	     * @param gwdefinition
	     * @return
	     */

	    @PostMapping("/add")
	    public String add(@RequestBody GatewayRouteDefinition gwdefinition) {
	        try {
	            RouteDefinition definition = assembleRouteDefinition(gwdefinition);
	            return this.dynamicRouteService.add(definition);
	        } catch (Exception e) {
	            e.printStackTrace();
	            return "fail";
	        }
	        
	    }
	    
	    /**
	     * 删除路由
	     * @param id 路由ID
	     * @return
	     */

	    @DeleteMapping("/delete/{id}")
	    public String delete(@PathVariable String id) {
	        return this.dynamicRouteService.delete(id);
	    } 
	    /**
	     * 更新途程
	     * @param gwdefinition
	     * @return
	     */

	    @PostMapping("/update")
	    public String update(@RequestBody GatewayRouteDefinition gwdefinition) {
	        RouteDefinition definition = assembleRouteDefinition(gwdefinition);
	        return this.dynamicRouteService.update(definition);
	    }
	    

	    
	    /**
	     * 將gwdefinition 轉 RouteDefinition
	     * @param gwdefinition 
	     * @return RouteDefinition 路由定義
	     */
	    private RouteDefinition assembleRouteDefinition(GatewayRouteDefinition gwdefinition) {
	        RouteDefinition definition = new RouteDefinition();
	        List<PredicateDefinition> pdList=new ArrayList<>();
	        definition.setId(gwdefinition.getId());
	        List<GatewayPredicateDefinition> gatewayPredicateDefinitionList=gwdefinition.getPredicates();
	        for (GatewayPredicateDefinition gpDefinition: gatewayPredicateDefinitionList) {
	            PredicateDefinition predicate = new PredicateDefinition();
	            predicate.setArgs(gpDefinition.getArgs());
	            predicate.setName(gpDefinition.getName());
	            pdList.add(predicate);
	        }
	        definition.setPredicates(pdList);
	        URI uri = UriComponentsBuilder.fromHttpUrl(gwdefinition.getUri()).build().toUri();
	        definition.setUri(uri);
	        return definition;
	}
}

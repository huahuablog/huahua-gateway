package com.delta.mes.gateway.service;

import java.sql.SQLException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.delta.mes.function.dao.BaseDao;
import com.delta.mes.function.service.BaseServices;
import com.delta.mes.gateway.entity.APIAuthorityEntity;

/**
 * API 身份驗證service
 * @author YONGHUI.ZHI
 *
 */
@Service
public class APIAuthService extends BaseServices<BaseDao> {
	
	public APIAuthService() {
		super(LoggerFactory.getLogger(APIAuthService.class));
	}
	public APIAuthService(Logger log) {
		super(log);
	}
	/**
	 * 
	 * @param path   請求的接口
	 * @param method 請求的方法
	 * @return       返回接口對應的實體
	 * @throws Exception
	 */
	public APIAuthorityEntity getAPIAuthEntity(String path, String method) throws Exception {
		String sql = " SELECT t.api_path_name,t.auth_validate_flag,t.request_method,t.controller,t.interval " +
				" FROM SFCS.C_MES_INTERFACE_AUTHORITY_T t where t.api_path_name = ? and t.request_method = ?";
		return this.query(null, sql, APIAuthorityEntity.class, new Object[]{path,method}).get(0);
	}
	
	/**
	 * @param tokenID	請求者的ID
	 * @param path		請求的接口
	 * @return			返回接口對應的Controller
	 * @throws SQLException
	 */
	public String getInterfaceController(String tokenID,String path) throws SQLException{
		String sql="SELECT f.controller FROM SFCS.C_MES_INTERFACE_RELATION_T r inner join C_MES_INTERFACE_TOKEN_T t\n" +
						"on r.token_id=t.token_id  inner join C_MES_INTERFACE_AUTHORITY_T f\n" + 
						"on r.interface_fun_id=f.interface_fun_id where t.valid_flag='0' and r.token_id=? and f.api_path_name=?";
		
		return (String) this.getSingleColumn(null, sql, new Object[]{tokenID,path});
	}
	
	/**
	 * @param tokenID	請求者ID
	 * @param path		請求的接口
	 * @return			返回MD5加密用的密鑰
	 * @throws SQLException
	 */
	public String getSecretKey(String tokenID,String path) throws SQLException{
		String sql="SELECT t.secret_key||'' FROM SFCS.C_MES_INTERFACE_RELATION_T r inner join C_MES_INTERFACE_TOKEN_T t\n" +
						"on r.token_id=t.token_id  inner join C_MES_INTERFACE_AUTHORITY_T f\n" + 
						"on r.interface_fun_id=f.interface_fun_id where t.valid_flag='0' and r.token_id=? and f.api_path_name=? ";
		
		return (String) this.getSingleColumn(null, sql, new Object[]{tokenID,path});
	}

}

package com.delta.mes.gateway.globalfilter;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.NettyDataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;

import com.alibaba.fastjson.JSON;
import com.delta.mes.action.Constants;

import com.delta.mes.gateway.entity.APIAuthorityEntity;
import com.delta.mes.gateway.service.APIAuthService;
import com.delta.mes.util.RedisServiceUtil;
import com.delta.mes.util.StringUtil;

import io.netty.buffer.ByteBufAllocator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * 身份驗證 globalfilter
 * 
 * @author YONGHUI.ZHI
 *
 */
public class AuthorizeGatewayGlobalFilter implements GlobalFilter {

	private static final Logger log = LoggerFactory.getLogger(AuthorizeGatewayGlobalFilter.class);
	private static final String AUTHORIZE_TOKEN = "tokenID";
	private static final APIAuthService service = new APIAuthService(log);
	
	 @Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		String contentType;
		boolean formdataType=false;
		String postBody = "";
		String param = "";
		String ip = "";
		String tokenID = "";
		ServerHttpRequest req = exchange.getRequest();
		ServerHttpResponse rep = exchange.getResponse();
		String path = req.getURI().getPath();
		URI requestUri = req.getURI();
		String method = req.getMethod().name();
		String schema = requestUri.getScheme();
        if ((!"http".equals(schema) && !"https".equals(schema))){
            return chain.filter(exchange);
        }
        AccessRecord accessRecord = new AccessRecord();
        accessRecord.setPath(requestUri.getPath());
        accessRecord.setQueryString(req.getQueryParams());
        exchange.getAttributes().put("startTime", System.currentTimeMillis());
        ip = exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();
		try {
			APIAuthorityEntity entity = null;
			try {
			entity = AuthorizeGatewayGlobalFilter.service.getAPIAuthEntity(path, method);
			}catch(IndexOutOfBoundsException e) {
				//沒配置第三方 不驗證
				return chain.filter(exchange);
			}
			
			
			if (entity != null) {
				param = req.getURI().getQuery();
				contentType = exchange.getRequest().getHeaders().getFirst("Content-Type");
				if(!StringUtil.isEmpty(contentType)) {
					formdataType=contentType.startsWith("multipart/form-data");
				}
				// 獲取postbody
				if ("POST".equals(method) && !formdataType) {
					// 二次封裝		        
					postBody = resolveBodyFromRequest(req);
					//postBody = exchange.getAttribute("cachedRequestBodyObject");
		            //下面将请求体再次封装写回到 request 里,传到下一级.
		            URI ex = UriComponentsBuilder.fromUri(requestUri).build(true).toUri();
		            ServerHttpRequest newRequest = req.mutate().uri(ex).build();
		            DataBuffer bodyDataBuffer = stringBuffer(postBody);
		            Flux<DataBuffer> bodyFlux = Flux.just(bodyDataBuffer);
		            newRequest = new ServerHttpRequestDecorator(newRequest) {
		                @Override
		                public Flux<DataBuffer> getBody() {
		                    return bodyFlux;
		                }
		            };
		            //System.out.println(postBody);
		            accessRecord.setBody(formatStr(postBody));
		            ServerWebExchange newExchange = exchange.mutate().request(newRequest).build();
		            exchange = newExchange;
				}
				tokenID = req.getHeaders().getFirst(AUTHORIZE_TOKEN);
				if (tokenID == null) {
					tokenID = req.getQueryParams().getFirst(AUTHORIZE_TOKEN);
				}
				log.info("IP:{},TIME:{},URI:{},TokenID:{},params:{},body:{}",ip, LocalDateTime.now(), path, tokenID, param,postBody);
				// 身份驗證
				if (!authorityValidate(entity, tokenID, param, postBody, path)) {
					log.warn("authority Check Fail.IP:{},URI:{},TokenID:{}",ip,path,tokenID);
					rep.setStatusCode(HttpStatus.UNAUTHORIZED);
					byte[] bytes = "UNAUTHORIZED, please check tokenID or sign value".getBytes(StandardCharsets.UTF_8);
			        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
			        return exchange.getResponse().writeWith(Flux.just(buffer));
				}
				
				// 請求頻率限制
				if (!requestlimit(entity, tokenID, ip)) {
					log.warn("No Frequent Access/禁止频繁访问，API:{},token:{},IP:{},Interval:{}",entity.getApiPath(),tokenID,ip,entity.getInterval());
					rep.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
					byte[] bytes = "No Frequent Access/禁止频繁访问".getBytes(StandardCharsets.UTF_8);
			        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
			        return exchange.getResponse().writeWith(Flux.just(buffer));
				}
			}
			return returnMono(chain, exchange, accessRecord);
		} catch (Exception e) {
			log.error("IP:{},URI:{},TokenID:{},Exception:{}", ip, path,tokenID, e);
			rep.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
			return rep.setComplete();
		}

	}

	/**
	 * 身份驗證
	 * 
	 * @param entity
	 *            API身份實體
	 * @param req
	 *            請求
	 * @param rep
	 *            響應
	 * @param param
	 *            0 Params 1 body  2 Path
	 * @return
	 */
	public boolean authorityValidate(APIAuthorityEntity entity, String tokenID,
			String... param) {
		String className = null;

		if (entity == null) {
			// 沒配API 驗證失敗
			return false;
		} else if (entity.getValidFlag().equals("0")) {
			// 0 不處理
			// return true;
		} else {
			if (StringUtils.isEmpty(tokenID)) {
				// token為空 驗證失敗
				return false;
			} else {
				Map<String, String> paramsMap = new HashMap<>();
				if (!StringUtils.isEmpty(param[0])) {
					String paramList[] = param[0].split("&");
					for (int i = 0; i < paramList.length; i++) {
						String item[] = paramList[i].split("=");
						paramsMap.put(item[0], item[1]);
					}
				}

				// 選擇Path的驗證條件
				switch (entity.getValidFlag()) {
				// 只根據tokenID判斷
				case "1":
					try {
						className = AuthorizeGatewayGlobalFilter.service.getInterfaceController(tokenID,
								entity.getApiPath());
					} catch (SQLException e) {
						className = null;
						e.printStackTrace();
					}
					if (StringUtils.isEmpty(className)) {
						return false;
					}
					break;
				// MD5簽名驗證
				case "2":
					if (!checkMD5Sign(tokenID, entity.getApiPath(), paramsMap, param[1])) {
						return false;
					}
					break;
				default:
					break;
				}
			}
		}
		return true;

	}

	/**
	 * 驗證MD5
	 * 
	 * @param tokenID
	 * @param path
	 * @param paramsMap
	 * @param body
	 * @return
	 */
	private boolean checkMD5Sign(String tokenID, String path, Map<String, String> paramsMap, String body) {
		String sign = paramsMap.get("sign");
		

		if (StringUtil.isEmpty(sign)) {
			return false;
		}

		String[] keys = paramsMap.keySet().toArray(new String[0]);
		Arrays.sort(keys);
		StringBuilder strBuilder = new StringBuilder();
		for (String key : keys) {
			String value = paramsMap.get(key);

			// 不處理sign以及value為空的參數
			if (key.equals("sign") || StringUtil.isEmpty(value)) {
				continue;
			}
			strBuilder.append(key).append(value);
		}
		// 若是Post請求時，有body，則在最後添加
		if (!StringUtil.isEmpty(body)) {
			strBuilder.append(body);
		}
		// 第三步：使用MD5C加密
		String secret;
		try {
			secret = AuthorizeGatewayGlobalFilter.service.getSecretKey(tokenID, path);
		} catch (SQLException e) {
			secret = null;
			e.printStackTrace();
		}
		if (StringUtil.isEmpty(secret)) {
			return false;
		}
		byte[] bytes = encryptMD5(strBuilder.toString(), secret);
		// 第四步：把二进制转化为大写的十六进制
		String tarSign = byte2hex(bytes);

		return sign.equals(tarSign);
	}

	/**
	 * MD5加密
	 * 
	 * @param data
	 * @param secret
	 * @return
	 */
	private byte[] encryptMD5(String data, String secret) {
		byte[] bytes = null;
		String tmpStr = secret + data;
		try {
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			// 加密后的字符串
			return md5.digest(tmpStr.getBytes(Constants.ENCODE));
		} catch (GeneralSecurityException | UnsupportedEncodingException e) {
			log.error("Encrypt MD5 Fail.", e.getMessage());
		}
		return bytes;
	}

	/**
	 * btye 轉 hex
	 * 
	 * @param bytes
	 * @return
	 */
	private String byte2hex(byte[] bytes) {
		StringBuilder sign = new StringBuilder();
		for (int i = 0; i < bytes.length; i++) {
			String hex = Integer.toHexString(bytes[i] & 0xFF);
			if (hex.length() == 1) {
				sign.append("0");
			}
			sign.append(hex.toUpperCase());
		}
		return sign.toString();
	}

	/**
	 * 請求頻率限制，兩次請求間隔不能少於間隔限制
	 * 
	 * @param entity
	 * @param tokenID
	 *            tokenID
	 * @param ip
	 *            請求IP
	 * @return false 不通過 true 通過
	 */
	private boolean requestlimit(APIAuthorityEntity entity, String tokenID, String ip) {
		// 限制時間間隔
		long interval = entity.getInterval();
		// 當前時間
		long thisTime = System.currentTimeMillis();
		// by IP 卡調用頻率
		if (entity.getValidFlag().equals("0")) {
			return predicateReqRedis(ip,entity.getApiPath(),thisTime,interval);
		} else {
			return predicateReqRedis(tokenID,entity.getApiPath(),thisTime,interval);
		}
	}
	
	/**
	 * 判斷頻率
	 * @param key tokenID or ip
	 * @param path API path
	 * @param thisTime 當前時間
	 * @param interval 時間間隔
	 * @return
	 */
	public boolean predicateReqRedis(String key,String path, long thisTime,long interval ) {
		if (!RedisServiceUtil.keyIsExists(key)) {
			// 首次調用
			RedisServiceUtil.setValue(key,  path, String.valueOf(thisTime));
		} else {
			if (!RedisServiceUtil.keyIsExists(key,  path)) {
				//首次調用此接口
				RedisServiceUtil.setValue(key,  path, String.valueOf(thisTime));
			} else {
				long lastTime = Long.valueOf(RedisServiceUtil.getValue(key,  path));
				if (thisTime - lastTime >= interval * 1000) {
					RedisServiceUtil.setValue(key,  path, String.valueOf(thisTime));
				} else {
					return false;
				}
			}
		}
		return true;
	}

    private Mono<Void> returnMono(GatewayFilterChain chain,ServerWebExchange exchange, AccessRecord accessRecord){
        return chain.filter(exchange).then(Mono.fromRunnable(()->{
            Long startTime = exchange.getAttribute("startTime");
            if (startTime != null){
                long executeTime = (System.currentTimeMillis() - startTime);
                accessRecord.setExpendTime(executeTime);
                accessRecord.setHttpCode(Objects.requireNonNull(exchange.getResponse().getStatusCode()).value());
                writeAccessLog(JSON.toJSONString(accessRecord) + "\r\n");
            }
        }));
    }
	
	/**
     * 获取请求体中的字符串内容
     * @param serverHttpRequest
     * @return
     */
    private String resolveBodyFromRequest(ServerHttpRequest serverHttpRequest){
        //获取请求体
        Flux<DataBuffer> body = serverHttpRequest.getBody();
        StringBuilder sb = new StringBuilder();

        body.subscribe(buffer -> {
            byte[] bytes = new byte[buffer.readableByteCount()];
            buffer.read(bytes);
            DataBufferUtils.release(buffer);
            String bodyString = new String(bytes, StandardCharsets.UTF_8);
            sb.append(bodyString);
        });
        return sb.toString();

    }

    /**
     * 去掉空格,换行和制表符
     * @param str
     * @return
     */
    private String formatStr(String str){
        if (str != null && str.length() > 0) {
            Pattern p = Pattern.compile("\\s*|\t|\r|\n");
            Matcher m = p.matcher(str);
            return m.replaceAll("");
        }
        return str;
    }

    private DataBuffer stringBuffer(String value){
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        NettyDataBufferFactory nettyDataBufferFactory = new NettyDataBufferFactory(ByteBufAllocator.DEFAULT);
        DataBuffer buffer = nettyDataBufferFactory.allocateBuffer(bytes.length);
        buffer.write(bytes);
        return buffer;
    }

    /**
     * 访问记录对象
     */
    private class AccessRecord{
        private String path;
        private String body;
        private MultiValueMap<String,String> queryString;
        private long expendTime;
        private int httpCode;
		public String getPath() {
			return path;
		}
		public void setPath(String path) {
			this.path = path;
		}
		public String getBody() {
			return body;
		}
		public void setBody(String body) {
			this.body = body;
		}
		public MultiValueMap<String, String> getQueryString() {
			return queryString;
		}
		public void setQueryString(MultiValueMap<String, String> queryString) {
			this.queryString = queryString;
		}
		public long getExpendTime() {
			return expendTime;
		}
		public void setExpendTime(long expendTime) {
			this.expendTime = expendTime;
		}
		public int getHttpCode() {
			return httpCode;
		}
		public void setHttpCode(int httpCode) {
			this.httpCode = httpCode;
		}
    }

    private void writeAccessLog(String str){
        File file = new File("access.log");
        if (!file.exists()){
            try {
                if (file.createNewFile()){
                    file.setWritable(true);
                }
            } catch (IOException e) {
                log.error("创建访问日志文件失败.{}",e.getMessage(),e);
            }
        }

        try(FileWriter fileWriter = new FileWriter(file.getName(),true)){
            fileWriter.write(str);
        } catch (IOException e) {
            log.error("写访问日志到文件失败. {}", e.getMessage(),e);
        }

    }

}

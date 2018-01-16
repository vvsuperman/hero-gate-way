package com.itmuch.cloud.gateway.mapper;

public interface UserTokenMapper {
	/**根据token获取userid*/
	String getUserByToken(String token);

}

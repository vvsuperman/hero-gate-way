package com.itmuch.cloud.gateway;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SetOperations;

import com.itmuch.cloud.gateway.mapper.UserTokenMapper;
import com.itmuch.cloud.gateway.util.CommonConstants;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

public class AccessFilter extends ZuulFilter  {

    private static Logger log = LoggerFactory.getLogger(AccessFilter.class);
    
    @Autowired
    private SetOperations<String,String> setOperations;
    
    @Autowired
    private HashOperations<String, String, String> hashOperations;
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    @Autowired
    private UserTokenMapper userTokenMapper;

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() {
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();

        log.info(String.format("%s request to %s", request.getMethod(), request.getRequestURL().toString()));

        String accessToken = request.getParameter("accessToken");
        if(accessToken == null) {
            log.warn("access token is empty");
            ctx.setSendZuulResponse(false);
            ctx.setResponseStatusCode(401);
            return null;
        }else {
        		String uid = userTokenMapper.getUserByToken(accessToken);
        		
        }
        log.info("access token ok");
        return null;
    }
    
    /** 用户纬度的节流，防止非法访问，并发等等 */
	public synchronized boolean access(String userId) {
		String key = genKey(userId);
		double intervalPerPermit = CommonConstants.TOKEN_INTERVAL * 1.0 / CommonConstants.TOKEN_LIMIT;
		Map<String, String> counter = hashOperations.entries(key);
		/** 如果当前用户还没有入令牌桶，则加入统计*/
		if (counter.size() == 0) {
			TokenBucket tokenBucket = new TokenBucket(System.currentTimeMillis(), CommonConstants.TOKEN_LIMIT - 1);
			hashOperations.putAll(key, tokenBucket.toHash());
			return true;
		} else {
			TokenBucket tokenBucket = TokenBucket.fromHash(counter);
			long lastRefillTime = tokenBucket.getLastRefillTime();
			long refillTime = System.currentTimeMillis();
			long intervalSinceLast = refillTime - lastRefillTime;
			long currentTokensRemaining;
			/** 当前访问发生在一个新的计时周期，则注满令牌桶 */
			if (intervalSinceLast > CommonConstants.TOKEN_INTERVAL) {
				currentTokensRemaining = CommonConstants.TOKEN_LIMIT;
			} else {
			/** 当前访问发生在先有的计时周期中，计算出令牌桶中 可用于访问的令牌数＝原有令牌数 + 新增的令牌数 */	
				long grantedTokens = (long) (intervalSinceLast / intervalPerPermit);
				currentTokensRemaining = Math.min(grantedTokens + tokenBucket.getTokensRemaining(), CommonConstants.TOKEN_LIMIT);
			}
			assert currentTokensRemaining >= 0;
			/** 令牌已用完,返回false，不可访问 */
			if (currentTokensRemaining == 0) {
				tokenBucket.setTokensRemaining(currentTokensRemaining);				
				hashOperations.putAll(key, tokenBucket.toHash());
				return false;
			} else {
			    /** 令牌未用完，设置最后获取令牌的时间 */
				tokenBucket.setLastRefillTime(refillTime);
				/** 令牌未用完，设置当前还剩下的令牌数 */
				tokenBucket.setTokensRemaining(currentTokensRemaining - 1);
				hashOperations.putAll(key, tokenBucket.toHash());
				return true;
			}
		}
	}
    
    /**根据userid生成 */
    private String genKey(String userId) {
        return "rate:limiter:" + CommonConstants.TOKEN_INTERVAL + ":" + CommonConstants.TOKEN_LIMIT + ":" + userId;
    }

    private static class TokenBucket {

        private long lastRefillTime;
        private long tokensRemaining;

        public TokenBucket(long lastRefillTime, long tokensRemaining){
            this.lastRefillTime = lastRefillTime;
            this.tokensRemaining = tokensRemaining;
        }

        public long getTokensRemaining() {
            return this.tokensRemaining;
        }

        public void setTokensRemaining(long tokensRemaining) {
            this.tokensRemaining = tokensRemaining;
        }

        public long getLastRefillTime() {
            return this.lastRefillTime;
        }

        public void setLastRefillTime(long lastRefillTime) {
            this.lastRefillTime = lastRefillTime;
        }

        public Map<String, String> toHash() {
            Map<String, String> hash = new HashMap<>();
            hash.put("lastRefillTime", String.valueOf(lastRefillTime));
            hash.put("tokensRemaining", String.valueOf(tokensRemaining));
            return hash;
        }

        public static TokenBucket fromHash(Map<String, String> hash) {
            long lastRefillTime = Long.parseLong(hash.get("lastRefillTime"));
            int tokensRemaining = Integer.parseInt(hash.get("tokensRemaining"));
            return new TokenBucket(lastRefillTime, tokensRemaining);
        }
    }

}
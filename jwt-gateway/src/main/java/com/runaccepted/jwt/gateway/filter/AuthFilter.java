package com.runaccepted.jwt.gateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.runaccepted.jwt.api.constant.JwtConstant;
import com.runaccepted.jwt.api.to.R;
import com.runaccepted.jwt.gateway.utils.JwtUtils;
import io.jsonwebtoken.Claims;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

@Slf4j
@Component
@ConfigurationProperties(prefix = "auth.skip")
@Data
public class AuthFilter implements GlobalFilter, Ordered {

    private List<String> uris;

    private List<String> checktoken;

    @Value("${jwt.blacklist.format}")
    private String jwtBlacklist;

    @Value("${jwt.token.format}")
    private String jwtToken;


    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    StringRedisTemplate redisTemplate;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {


        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().add("Content-Type","application/json; charset=utf-8");

        String path = request.getURI().getPath();

        //如果访问路径在定义过滤路径之中，直接放行
        boolean containUri=this.uris.contains(path);
        if (containUri){
            return chain.filter(exchange);
        }
        log.error("放行路径{},当前路径 {}，是否放行 {}",Arrays.asList(uris),path,containUri);

        String token = "";
        //得到请求头中Authorization的token值
        List<String> tokenHead = request.getHeaders().get(JwtConstant.tokenHeader);
        if (tokenHead!=null){
            token=tokenHead.get(0);
        }

        //验证token
        //没有token，没有权限
        if (StringUtils.isEmpty(token)){

            //50000: no token
            DataBuffer dataBuffer = createResponseBody(50000,"无访问权限",response);

            return response.writeWith(Flux.just(dataBuffer));
        }

        //有token，token不合法
        Claims claim = jwtUtils.getClaimsFromToken(token);
        if(claim==null){
            //50008: Illegal token
            DataBuffer dataBuffer = createResponseBody(50008,"非法token",response);
            return response.writeWith(Flux.just(dataBuffer));
        }

        String username = jwtUtils.getUserNameFromToken(token);
        String id = jwtUtils.getUserIdFromToken(token);
        String group = jwtUtils.getGroupFromToken(token);
        //没有有效载荷，token定义为非法
        if (StringUtils.isEmpty(username)
                ||StringUtils.isEmpty(id)
                ||StringUtils.isEmpty(group)){
            DataBuffer dataBuffer = createResponseBody(50008,"非法token",response);
            return response.writeWith(Flux.just(dataBuffer));
        }

        //token可用性判断后 才可以刷新和重新登录
        boolean checkUri = this.checktoken.contains(path);
        if (checkUri){
            return chain.filter(exchange);
        }
        log.error("验证token后放行路径{},当前路径 {}，是否放行 {}",Arrays.asList(checktoken),path,checkUri);


        //有token，但已被加入黑名单,只能选择再登录
        String key = String.format(jwtBlacklist,group);
        String blackToken=redisTemplate.opsForValue().get(key);
        if (!StringUtils.isEmpty(blackToken)){

            //50010: Token out;
            DataBuffer dataBuffer = createResponseBody(50010,username+" 已登出",response);

            return response.writeWith(Flux.just(dataBuffer));
        }

        // redis中id对应的token不存在
        // 或者请求中的token和redis中活跃的token不匹配，只能选择再登录
        String redisToken = (String)redisTemplate.opsForHash().get(jwtToken,id);
        //为空说明 被 注销/重新登录 操作删除
        if (StringUtils.isEmpty(redisToken)||!redisToken.equals(token)){
            //50010: Token out;
            DataBuffer dataBuffer = createResponseBody(50010,username+" 信息不匹配，无法继续操作",response);
            return response.writeWith(Flux.just(dataBuffer));
        }

        //有身份，过免登录时间
        if(!jwtUtils.isHoldTime(token)){

            //50014: Token expired;
            DataBuffer dataBuffer = createResponseBody(50014,"token过期",response);
            return response.writeWith(Flux.just(dataBuffer));
        }

        //token有效期内，可以进行登出
        boolean expiredTimeUri = path.equals("/jwt-client/logout");
        if (expiredTimeUri){
            return chain.filter(exchange);
        }
        log.error("当前路径 {}，是否放行 {}",path,expiredTimeUri);

        //token 失效
        if(jwtUtils.canRefresh(token)){

            String refreshToken =  jwtUtils.refreshToken(token);
            //更新请求头
            ServerHttpRequest httpRequest = request.mutate().header(JwtConstant.tokenHeader, refreshToken).build();
            ServerWebExchange webExchange = exchange.mutate().request(httpRequest).build();
            return chain.filter(webExchange);
        }
        return chain.filter(exchange);


    }

    private DataBuffer createResponseBody(int code,String message,ServerHttpResponse response){

        R result = R.error().code(code).message(message);
        ObjectMapper objectMapper = new ObjectMapper();
        String str="";
        try {
            str=objectMapper.writeValueAsString(result);
        } catch (JsonProcessingException e) {
           log.error("json转换错误 {}",e.getLocalizedMessage());
        }
        DataBuffer dataBuffer = response.bufferFactory().wrap(str.getBytes());
        return dataBuffer;
    }
    @Override
    public int getOrder() {
        return 0;
    }
}

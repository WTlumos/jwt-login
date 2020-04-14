package com.runaccepted.jwt.client.controller;

import com.runaccepted.jwt.api.constant.JwtConstant;
import com.runaccepted.jwt.api.entity.Admin;
import com.runaccepted.jwt.api.to.R;
import com.runaccepted.jwt.client.utils.JwtUtils;
import io.jsonwebtoken.Claims;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/jwt-client")
@Slf4j
public class ClientController {

    @Autowired
    JwtUtils jwtUtils;

    @Value("${login.id}")
    private String id;

    @Value("${login.username}")
    private String username;

    @Value("${login.password}")
    private String password;

    @Value("${jwt.username.format}")
    private String jwtUsername;

    @Value("${jwt.blacklist.format}")
    private String jwtBlacklist;

    @Value("${jwt.token.format}")
    private String jwtToken;

    @Autowired
    StringRedisTemplate redisTemplate;

    @ApiOperation(value = "登录")
    @PostMapping("/login")
    public R login(@RequestBody Admin admin){

        if (!admin.equal(username,password)) {

            return R.error().message("账号或密码错误");

        }else{

            admin.setId(id);
            String key = String.format(jwtUsername,admin.getId());
            log.error("redis key: {}",key);
            //判断redis中是否存在该用户名
            String name = (String) redisTemplate.opsForValue().get(key);
            if (!StringUtils.isEmpty(name)){
                return R.error().message(name+" 已经登录！");
            }
            //成功生成token
            String token= jwtUtils.generateToken(admin);
            //用户名有效时间 - 用户免登录时间
            //得到jwt中的截止时间
            long time=jwtUtils.generateLoginDate().getTime();

            long expired = time-new Date().getTime();

            log.error("原始数据: {} redis {} 截止时间: {}",time,key,
                    new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(time)));
            //信息放入redis - set key value EX 10
            redisTemplate.opsForValue().set(key,admin.getUsername(),expired,TimeUnit.MILLISECONDS);
            //存当前id对应正在使用的token
            //hset key field value
            redisTemplate.opsForHash().put(jwtToken,admin.getId(),token);
            log.error("redis hashKey: {} field: {} token:{}",jwtToken,admin.getId(),token);
           return R.ok().data("token",token);

        }
    }

    @ApiOperation(value = "登录")
    @PostMapping("/relogin")
    public R relogin(@RequestBody Admin admin,HttpServletRequest request){

        if (!admin.equal(username,password)) {

            return R.error().message("账号或密码错误");

        }else{
            admin.setId(id);
            String token = request.getHeader(JwtConstant.tokenHeader);
            //删除用户名
            String userKey = String.format(jwtUsername,admin.getId());
            redisTemplate.delete(userKey);
            //删除用户token
            redisTemplate.opsForHash().delete(jwtToken,id);
            //token放入黑名单
            String group = jwtUtils.getGroupFromToken(token);
            long time= jwtUtils.generateLoginDate().getTime();
            long expired = time - new Date().getTime();
            log.error("黑名单 - 原始数据: {} redis {} 截止时间: {}",time,userKey,
                    new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(time)));

            String blackKey = String.format(jwtBlacklist,group);
            //可能token已过期
            if(expired>0) {
                redisTemplate.opsForValue().set(blackKey, token, expired, TimeUnit.MILLISECONDS);
            }

            //重新生成用户名有效时间 - 用户免登录时间
            admin.setId(id);
            String newToken = jwtUtils.generateToken(admin);
            //得到jwt中的截止时间
            time=jwtUtils.generateLoginDate().getTime();
            expired = time-new Date().getTime();

            log.error("重新登录 原始数据-: {} redis {} 截止时间: {}",time,userKey,
                    new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(time)));
            //信息放入redis - set key value EX 10
            redisTemplate.opsForValue().set(userKey,admin.getUsername(),expired,TimeUnit.MILLISECONDS);
            //存当前id对应正在使用的token
            //hset key field value
            redisTemplate.opsForHash().put(jwtToken,admin.getId(),newToken);
            log.error("redis hashKey: {} field: {} token:{}",jwtToken,admin.getId(),token);
            return R.ok().data("token",newToken);
        }
    }

    @ApiOperation(value = "根据jwt得到信息")
    @GetMapping("/getInfo")
    public R getInfo(HttpServletRequest request){

        String token = request.getHeader(JwtConstant.tokenHeader);

        log.info("请求头 {}",token);

        String username = jwtUtils.getUserNameFromToken(token);

        return R.ok().data("username",username);
    }

    @ApiOperation(value = "清除token，登入")
    @GetMapping("/logout")
    public R logout(HttpServletRequest request){

        String token = request.getHeader(JwtConstant.tokenHeader);

        log.info("logout 请求头 {}",token);

        String id = jwtUtils.getUserIdFromToken(token);
        //删除登录的用户名
        String userKey = String.format(jwtUsername,id);
        redisTemplate.delete(userKey);

        //删除id当前使用的token
        redisTemplate.opsForHash().delete(jwtToken,id);
        //token放入黑名单
        String group = jwtUtils.getGroupFromToken(token);
        long time= jwtUtils.getLoginDate(token);
        long expired = time - new Date().getTime();
        log.error("logout 原始数据: {} redis {} 截止时间: {}",time,userKey,
                new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(time)));
        String blackKey = String.format(jwtBlacklist,group);
        if (expired>0) {
            redisTemplate.opsForValue().set(blackKey, token, expired, TimeUnit.MILLISECONDS);
        }

        return R.ok().message("注销成功");
    }

    @ApiOperation(value = "刷新token")
    @GetMapping(value = "/token/refresh")
    public Object refreshToken(HttpServletRequest request) {
        //1、获取请求头中的Authorization完整值
        String oldToken = request.getHeader(JwtConstant.tokenHeader);
        String refreshToken = "";

        //2、是否可以进行刷新（未过有效时间/是否在免登录范围）
//        if(!jwtUtils.canRefresh(oldToken)|| jwtUtils.isHoldTime(oldToken)){
//            return R.error().message("jwt还未失效，无需刷新").code(20001);
//        }

        //再次获得免登录机会
        long time = jwtUtils.generateLoginDate().getTime();
        long expired = time - new Date().getTime();

        refreshToken =  jwtUtils.refreshToken(oldToken);

        String id = jwtUtils.getUserIdFromToken(refreshToken);
        //原token放入黑名单
        String group = jwtUtils.getGroupFromToken(oldToken);
        String key = String.format(jwtBlacklist,group);
        if (expired>0) {
            redisTemplate.opsForValue().set(key, oldToken, expired, TimeUnit.MILLISECONDS);
        }
        //当前使用的token进行修改
        redisTemplate.opsForHash().put(jwtToken,id,refreshToken);
        //更新用户有效时间
        String userkey = String.format(jwtUsername,id);

        redisTemplate.expire(userkey,expired,TimeUnit.MILLISECONDS);

        Date date = jwtUtils.getHoldTime(refreshToken);

        //将新的token交给前端
        return R.ok().data("token",refreshToken).data("date",date);
    }
}

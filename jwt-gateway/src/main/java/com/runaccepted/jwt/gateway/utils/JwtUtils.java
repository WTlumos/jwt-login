package com.runaccepted.jwt.gateway.utils;

import com.runaccepted.jwt.api.constant.JwtConstant;
import com.runaccepted.jwt.api.entity.Admin;
import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.text.SimpleDateFormat;
import java.util.*;

/**
 * JwtToken生成的工具类
 *
 * JWT token的格式：header.payload.signature
 *
 * header的格式（算法、token的类型）：
 * {"alg": "HS512","typ": "JWT"}
 * payload的格式（用户名、创建时间、生成时间）：
 *      {"id":1,"sub":"wang","created":1489079981393,"exp":1489684781}
 */
@Slf4j
@Component
public class JwtUtils {

	@Value("${jwt.subject.name}")
	private String SUBJECT;

	//秘钥
	@Value("${jwt.secret.key}")
	private String APPSECRET;

	//过期时间，毫秒，30分钟
	@Value("${jwt.expire.time}")
	private long EXPIRE;

	@Value("${jwt.hold.time}")
	private int holdTime;

	@Value("${jwt.hold.type}")
	private int holdType;

	/**
	 * 根据用户信息生成token
	 */
	public String generateToken(Admin admin) {
		Map<String, Object> claims = new HashMap<String, Object>();
		claims.put(JwtConstant.CLAIM_KEY_USERID, admin.getId());
		claims.put(JwtConstant.CLAIM_KEY_USERNAME, admin.getUsername());
		claims.put(JwtConstant.CLAIM_KEY_CREATED, new Date());
		claims.put(JwtConstant.CLAIM_KEY_HOLDTIME,generateLoginDate());
		claims.put(JwtConstant.CLAIM_KEY_GROUP,generateGroup());
		return generateToken(claims);
	}

	/**
	 * 根据负责生成JWT的token
	 */
	private String generateToken(Map<String, Object> claims) {
		return Jwts.builder()
				.setSubject(SUBJECT)
				.setClaims(claims)
				.setExpiration(generateExpirationDate())
				.signWith(SignatureAlgorithm.HS512, APPSECRET)
				.compact();
	}

	/**
	 * 从token中获取JWT中的负载
	 */
	public Claims getClaimsFromToken(String token) {
		Claims claims = null;
		try {
			claims = Jwts.parser()
					.setSigningKey(APPSECRET)
					.parseClaimsJws(token)
					.getBody();
		}catch (ExpiredJwtException e) {
			String id = (String) e.getClaims().get(JwtConstant.CLAIM_KEY_USERID);
			String username = (String) e.getClaims().get(JwtConstant.CLAIM_KEY_USERNAME);
			log.error("JWT载荷中 用户ID:{} 用户名:{}", id, username);

			claims=e.getClaims();
		} catch (MalformedJwtException e){
			log.error("Json格式错误 {}",e.getLocalizedMessage());
		} catch (SignatureException e){
			log.error("Json格式错误 {}",e.getLocalizedMessage());
		} catch(IllegalArgumentException e){
			log.error("错误 {}",e.getLocalizedMessage());
		}
		return claims;
	}

	/**
	 * 生成token的过期时间
	 */
	public Date generateExpirationDate() {
		return new Date(System.currentTimeMillis() + EXPIRE);
	}

	/**
	 * 生成token的免登录时间
	 */
	public Date generateLoginDate() {

		//有效期内可刷新token
		Calendar calendar = new GregorianCalendar();
		//当天+2
		calendar.add(holdType,holdTime);

		return calendar.getTime();
	}

	/**
	 * 生成token的group
	 */
	public String generateGroup() {

		String group = UUID.randomUUID().toString();
		group = group.replace(".","");

		return group;
	}

	/**
	 * 从token中获取登录用户名
	 */
	public String getUserNameFromToken(String token) {

		Claims claims = getClaimsFromToken(token);
		String username = (String) claims.get(JwtConstant.CLAIM_KEY_USERNAME);

		return username;
	}

	/**
	 * 从token中获取过期时间
	 */
	public Date getExpiredDateFromToken(String token) {
		Claims claims = getClaimsFromToken(token);
		Date expiredDate = claims.getExpiration();
		log.error("token中过期时间 {}", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(expiredDate));
		return expiredDate;
	}

	/**
	 * 从token中获取group
	 */
	public String getGroupFromToken(String token) {
		Claims claims = getClaimsFromToken(token);
		String group = (String)claims.get(JwtConstant.CLAIM_KEY_GROUP);
		log.error("token中的用户组 {}", group);
		return group;
	}

	/**
	 * 从token中获取登录用户名id
	 */
	public String getUserIdFromToken(String token) {
		Claims claims = getClaimsFromToken(token);
		String id = (String) claims.get(JwtConstant.CLAIM_KEY_USERID);
		return id;
	}

	/**
	 * 从token中获取登录截止时间
	 */
	public Date getHoldTime(String token){
		Claims claims = getClaimsFromToken(token);
		long dateTime = (long)claims.get(JwtConstant.CLAIM_KEY_HOLDTIME);
		Date date = new Date(dateTime);
		log.info("原数据值：{} 该token免登录时间截止至 {}",dateTime,
				new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(date));
		return date;
	}

	/**
	 * 验证token是否还有效
	 *
	 * @param token       客户端传入的token
	 * @param admin 从数据库中查询出来的用户信息
	 */
	public boolean validateToken(String token, Admin admin) {
		String username = getUserNameFromToken(token);
		return username.equals(admin.getUsername()) && !isTokenExpired(token);
	}

	/**
	 * 判断token是否已经失效
	 */
	public boolean isTokenExpired(Date expiredDate) {
		boolean before = new Date().before(expiredDate);
		return before;
	}

	/**
	 * 判断token是否已经失效
	 */
	public boolean isTokenExpired(String token) {
		Date expiredDate = getExpiredDateFromToken(token);
		boolean before = new Date().before(expiredDate);
		return before;
	}

	/**
	 * 免登录截止时间判断
	 */
	public boolean isHoldTime(String token){
		Date date = getHoldTime(token);
		return new Date().before(date);
	}
	/**
	 * 判断token是否可以被刷新
	 */
	public boolean canRefresh(String token) {
		return !isTokenExpired(token);
	}


	/**
	 * 刷新token
	 */
	public String refreshToken(String token) {
		Claims claims = getClaimsFromToken(token);
		claims.put(JwtConstant.CLAIM_KEY_CREATED, new Date());
		claims.put(JwtConstant.CLAIM_KEY_GROUP,generateGroup());
		//网关仅更新token有效期，不更新免登录时间
		//claims.put(JwtConstant.CLAIM_KEY_HOLDTIME,generateLoginDate());
		return generateToken(claims);
	}
}

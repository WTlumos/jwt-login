# jwt-login

#### 介绍

Jwt+Gateway+Nacos+Redis实现分布式下免登录

#### 整体设计

[Jwt+Gateway+nacos+redis实现免登录](https://www.runaccepted.com/2019/11/14/Jwt-Spring%E5%AE%9E%E7%8E%B03%E5%A4%A9%E5%85%8D%E7%99%BB%E5%BD%95/)

#### 安装教程

1.  安装redis https://redis.io/download
2.  安装nacos https://github.com/alibaba/nacos
3.  推荐安装Postman https://www.postman.com/downloads/

#### 使用说明

此为SpringBoot 2.2.6项目，运行在IDEA上

1.  redis 6379端口和nacos 8848端口开启服务
2.  运行jwt-gateway项目 9500端口和jwt-client项目
3.  运行http://localhost:9500/jwt-client/相关路由

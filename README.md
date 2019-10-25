# spring-security-demo

## RBAC

## LDAP
Lightweight Directory Access Protocol　轻量目录访问协议
### 定义
LDAP定义了：
 - 1、获取目录数据方法的协议。
 - 2、数据在目录服务中的展现方式。
 - 3、数据在目录服务中导入／导出的方式。
 
LDAP没有定义：
 - 1、数据的存储和操作方式。（数据的存储和获取往往由实现LDAP方法的特定事物数据库处理。）
### 数据结构
 - DIT(Directory Information Tree):在LDAP系统中数据以层级对象的形式展示。
 - attribute:每个attribute都有一个唯一的名字并包含存储的数据。attribute是一个或多个objectClass的成员。
 - objectClass:attribute的容器，定义了每个属性必须/可选存在。每个objectClass都有唯一的名字。
 - entry:DIT的节点。每个entry有任意数量的子节点以及一个父节点。每个entry是一个或多个objectClass的实例。
 - root:DIT的根节点。
 
![DIT](image/ldap-dit.png)
### 对比RDBMS
在性能上，RDBMS系统要明显优于LDAP，但LDAP有以下优势：
 - 1、LDAP提供了获取远程／本地数据的标准化接口。因此在替换LDAP实现时可以完全不影响外部的接口。RDBMS大多只实现了标准化的本地接口，远程接口往往是专有的。
 - 2、由于LDAP使用标准化接口，LDAP的客户端和服务端的开发／来源可以做到彼此独立。此外LDAP可以用于抽象面向事务的数据库包含的数据视图（比如运行用户查询）的同时允许用户透明的更改事务数据库。
 - 3、LDAP可以在不影响外部数据获取的情况下将数据移动到多个存储位置。只需要更改操作字段，LDAP的转介方法就可以将数据移动到可选的LDAP服务器。因此LDAP可以在数据来源与不同匿名组织的情况下构建分布式系统，同时向用户提供唯一且一致的数据视图。
 - 4、LDAP可以通过更改配置将数据复制到一个或多个LDAP服务器／应用，不需要增加代码或改变外部获取数据的方式。
### 使用Spring Security

## Spring Security
### java.security.Principal
接口，代表了一个主体的抽象概念，可以用于表示如个人、公司、登陆帐号等任何实体。

### org.springframework.security.core.context.SecurityContextHolderStrategy
接口，表明针对特定线程的安全上下文存储策略，有以下三种实现：

 - org.springframework.security.core.context.ThreadLocalSecurityContextHolderStrategy：接口的基本实现，变量contextHolder的类型为ThreadLocal<SecurityContext>
 - org.springframework.security.core.context.InheritableThreadLocalSecurityContextHolderStrategy：接口的基本实现，变量contextHolder的类型为InheritableThreadLocal<SecurityContext>
 - org.springframework.security.core.context.GlobalSecurityContextHolderStrategy：JVM中所有的实例共享一个安全上下文的策略，变量contextHolder的类型为SecurityContext
 
### org.springframework.security.core.context.SecurityContextHolder
存放安全上下文存储策略，安全上下文的get、set、create都通过操作strategy变量实现。

安全上下文存储策略通过设置java系统变量spring.security.strategy实现（可通过命令行参数或使用System.setProperty()设置），spring.security.strategy有以下三种值：

 - MODE_THREADLOCAL：默认的策略。对应ThreadLocalSecurityContextHolderStrategy。
 - MODE_INHERITABLETHREADLOCAL：对应InheritableThreadLocalSecurityContextHolderStrategy。
 - MODE_GLOBAL：对应InheritableThreadLocalSecurityContextHolderStrategy。
 
### org.springframework.security.core.context.SecurityContext
接口，定义与当前执行线程相关的最小安全信息。基本实现为SecurityContextImpl。

### org.springframework.security.core.Authentication
接口，一个请求被AuthenticationManager.authenticate()处理后，Authentication可以代表一个认证过的请求／主体并通过认证机制存储于由
SecurityContextHolder管理的SecurityContext中。此外，Authentication可以不使用认证机制，由
SecurityContextHolder.getContext().setAuthentication(anAuthentication)设置。

### org.springframework.security.core.GrantedAuthority
接口，代表一个对象被授予的权限。

### org.springframework.security.core.userdetails.UserDetails
接口,提供帐号、密码、过期、锁定、认证过期等主要用户信息。

### org.springframework.security.core.userdetails.UserDetailsService
接口，用于获取用户特定信息。主要作为DAO由org.springframework.security.authentication.dao.DaoAuthenticationProvider使用。只声明一个只读方法loadUserByUsername。

### org.springframework.security.access.intercept.AbstractSecurityInterceptor
抽象类，实现了对安全对象的拦截
### org.springframework.security.access.ConfigAttribute
接口，存放安全系统（RunAsManager、AccessDecisionManager）相关的配置。 
### RoleVoter
### AuthenticationEntryPoint
### UsernamePasswordAuthenticationToken 
### ExceptionTranslationFilter
### SecurityContextPersistenceFilter
### SecurityMetadataSource 
### AccessDecisionManager
### AuthenticationManager
### AfterInvocationManager
### RunAsManager
### ProviderManager
### UserDetailsManager
### AbstractSecurityInterceptor
### AspectJSecurityInterceptor
### FilterSecurityInterceptor
### MethodSecurityInterceptor
### AuthenticationProvider
### DaoAuthenticationProvider 
### LdapAuthenticationProvider 






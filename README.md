# bypass_http
一个可以绕过sni审查的实用工具，可以访问steam，pixiv和discord等网站  
可以使用两种方式，一种是直接使用make_request方法，继承了get和post方法，另一个是启动本地服务器进行代理中继，中继模式是在本地80端口创建服务器，将需要访问的域名host填写为127.0.0.1即可访问  
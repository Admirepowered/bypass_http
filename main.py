import socket
import ssl
import select
import threading
import httpx
import httpcore
def create_ssl_context():
    """创建自定义的 SSL 上下文"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False  # 不验证主机名
    context.verify_mode = ssl.CERT_NONE  # 不验证证书
    return context


def make_request(url, method="GET", data=None, headers=None):
    """
    通用的 HTTP 请求函数，支持 GET 和 POST 请求。
    
    :param url: 请求的 URL 地址。
    :param method: 请求的方法，默认为 "GET"。
    :param data: 传递给 POST 请求的数据，默认为 None。
    :param headers: 自定义的请求头，默认为 None。
    :return: 返回响应内容或错误信息。
    """
    hostname = url.split("//")[-1].split("/")[0]
    
    #hostname = "steamcommunity.com"  # 域名
    ip=found(hostname)
    
    if ip == None:
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror:
            print(f"无法解析域名: {hostname}")
            return ""  # 如果域名解析失败，返回空字符串
    print(f"request_ip:{ip}")
    request = url.replace(hostname,ip)
    context = create_ssl_context()
    try:
        # 使用自定义的 SSL 上下文，构建 httpx 的客户端
        with httpx.Client(verify=context) as client:
            if headers is None:
                headers = {"Host": hostname}
            else:
                headers["Host"] = hostname
                
            if method.upper() == "POST":
                response = client.post(request, headers=headers, data=data)
            else:
                response = client.get(request, headers=headers)
            # 手动设置目标 IP 并添加 Host Header
            #response = client.get(f"https://{ip}/", headers={"Host": hostname})
            print(f"状态码: {response.status_code}")
            #print(f"响应内容: {response.text}")
            return response.text
    except httpx.RequestError as e:
        # 处理请求中的错误
        print(f"请求错误: {e}")
        return ""
def test():
# 创建没有 SNI 的 SSL 上下文
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.check_hostname = False  # 不验证主机名
    context.verify_mode = ssl.CERT_NONE  # 不验证证书
    context.set_servername_callback(None)  # 禁用 SNI

    # 设置目标主机和端口
    ip = '2.16.174.204'
    hostname="steamcommunity.com"
    port = 443

    # 创建一个连接
    sock = socket.create_connection((ip, port))

    # 使用 SSL 上下文包装 socket，禁用 SNI
    ssl_sock = context.wrap_socket(sock, server_hostname=ip)

    # 构造 HTTP 请求
    request = f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"

    # 发送请求
    ssl_sock.sendall(request.encode())

    # 获取响应
    response = ssl_sock.recv(4096)

    # 打印响应（可以根据需要分批接收）
    print(response.decode('utf-8', errors='ignore'))

    # 关闭连接
    ssl_sock.close()


def found(domain):
    """根据域名返回对应的 IP 地址"""
    domain_list = ["steamcommunity.com:2.16.174.204", "baidu.com:127.0.0.2"]
    # 遍历列表，查找匹配的域名
    for entry in domain_list:
        # 按 ':' 分割域名和 IP
        domain_part, ip_part = entry.split(":")
        
        # 如果找到匹配的域名，返回对应的 IP
        if domain_part == domain:
            return ip_part
    
    # 如果没有找到，返回 None
    return None
def handle_client(client_socket):
    """通过 select 实现双向转发"""
    # 创建没有 SNI 的 SSL 上下文
    
    data = client_socket.recv(4096)
    if not data:
        # 客户端关闭连接
        client_socket.close()
        return
    else:
        # 替换数据中的 127.0.0.1 为 steamcommunity.com
        request_str = data.decode('utf-8')

        # 找到 'Host:' 字段的位置
        host_index = request_str.find('Host:')

        if host_index != -1:
            # 提取 Host: 后面的部分
            host_start = host_index + len('Host:')  # 'Host:' 的结束位置
            host_end = request_str.find('\r\n', host_start)  # 找到 '\r\n' 结束位置
            host = request_str[host_start:host_end].strip()
            print(f"Host: {host}")
            hostname=host
            port=443
            ip=found(hostname)
            if ip==None:
                print("Host ip not found")
                anser = f"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\ndomain is not host in this server"
                client_socket.sendall(anser.encode())
                client_socket.close()
                return
        else:
            print("Host not found")
            anser = f"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nRequest Host is needed"
            client_socket.sendall(anser.encode())
            client_socket.close()
            return
        
        data = data.replace(b'127.0.0.1', b'steamcommunity.com')
        print(data)
        
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.check_hostname = False  # 不验证主机名
    context.verify_mode = ssl.CERT_NONE  # 不验证证书
    context.set_servername_callback(None)  # 禁用 SNI
    
    # 设置目标主机和端口
    #ip = '2.16.174.204'
    #hostname = "steamcommunity.com"
    #port = 443

    # 创建一个连接
    sock = socket.create_connection((ip, port))

    # 使用 SSL 上下文包装 socket，禁用 SNI
    ssl_sock = context.wrap_socket(sock, server_hostname=ip)
    ssl_sock.sendall(data)
    # 创建一个 list 来监听客户端和目标服务器的 I/O
    inputs = [client_socket, ssl_sock]
    outputs = []

    # 循环使用 select 进行多路复用
    while True:
        # 使用 select 监听输入和输出事件
        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for s in readable:
            if s is client_socket:
                # 从客户端接收数据并发送到目标服务器
                data = client_socket.recv(4096)
                if not data:
                    # 客户端关闭连接
                    inputs.remove(client_socket)
                    client_socket.close()
                else:
                    # 替换数据中的 127.0.0.1 为 steamcommunity.com
                    data = data.replace(b'127.0.0.1', b'steamcommunity.com')
                    ssl_sock.sendall(data)
            elif s is ssl_sock:
                # 从目标服务器接收数据并发送回客户端
                data = ssl_sock.recv(4096)
                if not data:
                    # 目标服务器关闭连接
                    inputs.remove(ssl_sock)
                    ssl_sock.close()
                else:
                    client_socket.sendall(data)

        # 处理异常情况
        for s in exceptional:
            inputs.remove(s)
            s.close()

def start_proxy():
    """启动代理服务器，监听本地 80 端口"""
    LOCAL_HOST = '0.0.0.0'
    LOCAL_PORT = 80
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((LOCAL_HOST, LOCAL_PORT))
    server_socket.listen(5)
    print(f"代理服务启动，监听 {LOCAL_HOST}:{LOCAL_PORT} 端口")

    while True:
        # 等待客户端连接
        client_socket, addr = server_socket.accept()
        print(f"接收到来自 {addr} 的连接")

        # 为每个客户端连接创建一个新的线程来处理
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    #start_proxy()
    url = "https://steamcommunity.com/"
    test=make_request(url, method="GET")
    print(test)
import socket
import ssl
import select
import threading
import httpx
import httpcore
import struct
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

def disable_sni_forward(client_sock, target_ip, target_port):
    try:
        # 代理作为 TLS 服务端的 SSLContext
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certfile='server_cert.pem', keyfile='server_key.pem')

        # 将 client_sock 包装成 TLS 服务端 socket，解密客户端 TLS
        tls_client_sock = server_context.wrap_socket(client_sock, server_side=True)

        # 代理作为 TLS 客户端连接真实服务器
        client_context = ssl.create_default_context()
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE

        server_sock = socket.create_connection((target_ip, target_port))
        tls_server_sock = client_context.wrap_socket(server_sock, server_hostname=None)  # 可以关闭SNI或保留

        sockets = [tls_client_sock, tls_server_sock]

        while True:
            rlist, _, _ = select.select(sockets, [], [])
            for s in rlist:
                data = s.recv(4096)
                if not data:
                    # 一方断开，关闭所有连接
                    for sock in sockets:
                        sock.close()
                    return

                if s is tls_client_sock:
                    # 收到客户端发来的明文数据，转发给服务器（自动加密）
                    tls_server_sock.sendall(data)
                else:
                    # 收到服务器返回的明文数据，转发给客户端（自动加密）
                    tls_client_sock.sendall(data)

    except Exception as e:
        print(f"[!] 转发错误: {e}")
        client_sock.close()

def handle_socks5(client_sock):
    try:
        # 1. SOCKS5 greeting
        ver, nmethods = client_sock.recv(2)
        client_sock.recv(nmethods)
        client_sock.sendall(b'\x05\x00')  # no auth

        # 2. SOCKS5 request
        ver, cmd, _, atyp = client_sock.recv(4)
        if cmd != 1:
            client_sock.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            return

        if atyp == 3:  # domain name
            domain_len = client_sock.recv(1)[0]
            domain = client_sock.recv(domain_len).decode()
        else:
            print("仅支持域名连接")
            client_sock.close()
            return

        port = int.from_bytes(client_sock.recv(2), "big")

        if port != 443:
            print(f"[SKIP] 非 443 端口: {domain}:{port}")
            client_sock.close()
            return


        
        client_sock.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        
        ip = found(domain)
        print(f"[CONNECT] {domain}:{port} -> {ip}")
        if not ip:

            # 找不到映射IP，做透明TLS转发，客户端的TLS流量原封不动地转发给目标服务器
            print(f"[TRANSPARENT TLS FORWARD] {domain}:{port} -> direct TLS forwarding")

            # 直接建立到目标服务器的 TCP 连接
            remote_sock = socket.create_connection((domain, port))
            
            # 双向转发 client_sock <-> remote_sock（不做 TLS 解密）
            sockets = [client_sock, remote_sock]

            while True:
                rlist, _, _ = select.select(sockets, [], [])
                for s in rlist:
                    data = s.recv(4096)
                    if not data:
                        for sock in sockets:
                            sock.close()
                        return
                    if s is client_sock:
                        remote_sock.sendall(data)
                    else:
                        client_sock.sendall(data)
        else:
            
            # 找到 IP，执行 TLS MITM，代理承接TLS解密流量
            print(f"[MITM TLS FORWARD] {domain}:{port} -> {ip}")
            threading.Thread(target=disable_sni_forward, args=(client_sock, ip, port), daemon=True).start()
        #threading.Thread(target=disable_sni_forward, args=(client_sock, ip, port), daemon=True).start()
    except Exception as e:
        print(f"[!] 错误: {e}")
        client_sock.close()

def start_sock5_proxy():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 1080))
    s.listen(100)
    print("[*] SOCKS5 代理启动，监听 1080（仅 443 且禁用 SNI）")

    while True:
        client, addr = s.accept()
        threading.Thread(target=handle_socks5, args=(client,), daemon=True).start()

if __name__ == "__main__":
    #start_proxy()
    start_sock5_proxy()
    url = "https://steamcommunity.com/"
    test=make_request(url, method="GET")
    print(test)
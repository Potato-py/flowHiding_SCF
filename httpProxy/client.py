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
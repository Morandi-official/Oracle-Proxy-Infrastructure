"""Opt-in, bounded read-only performance controls. Never tune or disclose secrets."""
import concurrent.futures
import html
import json
import math
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request

MAX_DOWNLOAD=8*1024*1024
HEADERS=('server','via','x-cache','content-type')
OPEN=urllib.request.build_opener(urllib.request.ProxyHandler({}))


def metadata():
    try:
        request=urllib.request.Request('http://169.254.169.254/opc/v2/instance/',headers={'Authorization':'Bearer Oracle'})
        with OPEN.open(request,timeout=3) as response: value=json.loads(response.read(65537))
        config=value.get('shapeConfig',{})
        result={name:value.get(name) for name in ('shape','region')}
        result['shape_config']={key:config[key] for key in ('ocpus','memoryInGBs','networkingBandwidthInGbps','maxVnicAttachments') if key in config and isinstance(config[key],(int,float))}
        return result
    except (OSError,ValueError,TypeError): return {'status':'UNAVAILABLE'}


def local():
    result={'logical_cpus':os.cpu_count(),'load_average':list(os.getloadavg())}
    text=Path('/proc/meminfo').read_text()
    result['memory_kib']={key:int(value) for key,value in re.findall(r'^(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+)',text,re.M)}
    result['tcp_settings']={}
    for name in ('tcp_congestion_control','tcp_available_congestion_control','tcp_rmem','tcp_wmem'):
        path=Path('/proc/sys/net/ipv4')/name
        if path.exists():result['tcp_settings'][name]=path.read_text().strip()[:100]
    for name in ('rmem_max','wmem_max','netdev_max_backlog'):
        path=Path('/proc/sys/net/core')/name
        if path.exists():result['tcp_settings'][name]=path.read_text().strip()[:100]
    result['interface_counters']={}
    for directory in Path('/sys/class/net').iterdir():
        if directory.name=='lo':continue
        stats=directory/'statistics'
        result['interface_counters'][directory.name]={key:int((stats/key).read_text()) for key in ('rx_bytes','tx_bytes','rx_dropped','tx_dropped','rx_errors','tx_errors')}
    return result


def http_probe(label,url,limit=65536):
    started=time.monotonic()
    result={'target':label,'status':None,'bytes':0}
    try:
        request=urllib.request.Request(url,headers={'User-Agent':'OracleProxy-ReadOnly-Diagnostics/1','Accept-Encoding':'identity'})
        with OPEN.open(request,timeout=12) as response:
            result['ttfb_ms']=round((time.monotonic()-started)*1000)
            result['status']=response.status
            result['headers']={key:response.headers.get(key,'')[:160] for key in HEADERS}
            result['bytes']=len(response.read(limit))
    except Exception as error:
        result['error_category']=type(error).__name__
        if hasattr(error,'code'):result['status']=error.code
    result['elapsed_ms']=round((time.monotonic()-started)*1000)
    return result


def transfer(kind):
    started=time.monotonic();result={'kind':kind,'status':'UNAVAILABLE','bytes':0}
    try:
        if kind=='upload':
            data=bytes(2*1024*1024)
            request=urllib.request.Request('https://speed.cloudflare.com/__up',data=data,method='POST',headers={'Content-Type':'application/octet-stream'})
        else:
            data=None;request=urllib.request.Request('https://speed.cloudflare.com/__down?bytes='+str(MAX_DOWNLOAD),headers={'Accept-Encoding':'identity'})
        with OPEN.open(request,timeout=20) as response:
            result['http_status']=response.status
            if data is not None:
                response.read(1024);result['bytes']=len(data)
            else:
                while result['bytes']<MAX_DOWNLOAD:
                    block=response.read(min(65536,MAX_DOWNLOAD-result['bytes']))
                    if not block:break
                    result['bytes']+=len(block)
        elapsed=time.monotonic()-started
        result.update(status='OBSERVED',elapsed_ms=round(elapsed*1000),mbps=round(result['bytes']*8/max(elapsed,.001)/1_000_000,3))
    except Exception as error:result['error_category']=type(error).__name__
    return result


def official_shapes():
    result=[]
    urls=('https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm',
          'https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm')
    for url in urls:
        row={'url':url,'status':'UNAVAILABLE'}
        try:
            with OPEN.open(url,timeout=12) as response:raw=response.read(2*1024*1024).decode('utf-8','replace')
            text=html.unescape(re.sub('<[^>]+>',' ',raw));text=re.sub(r'\s+',' ',text)
            snippets=[]
            for match in re.finditer(r'50 Mbps|50 M[bB]|VM\.Standard\.E2\.1\.Micro|VM\.Standard\.A1\.Flex|480 Mbps|0\.48',text,re.I):
                snippets.append(text[max(0,match.start()-120):match.end()+500])
            row.update(status='OBSERVED',excerpts=snippets[:10])
        except Exception as error:row['error_category']=type(error).__name__
        result.append(row)
    return result


def observe():
    started=time.monotonic()
    result={'schema':1,'scope':'SERVER_DIRECT_NOT_WINDOWS_TUNNEL','instance':metadata(),'before':local()}
    targets=(('github','https://github.com/Morandi-official/Oracle-Proxy-Infrastructure'),
             ('avatars','https://avatars.githubusercontent.com/u/204281968?v=4&size=64'),
             ('raw','https://raw.githubusercontent.com/Morandi-official/Oracle-Proxy-Infrastructure/main/README.md'),
             ('assets','https://github.githubassets.com/assets/index-JVHuKBxQ.css'))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        result['github_http']=list(pool.map(lambda pair:http_probe(*pair),targets))
    result['transfers']=[transfer('download'),transfer('upload')]
    result['official_shape_sources']=official_shapes()
    result['after']=local();result['elapsed_ms']=round((time.monotonic()-started)*1000)
    return result


if __name__=='__main__':print(json.dumps(observe(),sort_keys=True))

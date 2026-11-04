"""Small read-only host sampler. No packet capture, process commands, or root required."""
import os
import time
from pathlib import Path


def text(root,path):return (root/path.lstrip('/')).read_text()

def sample(previous=None,root=Path('/'),now=None):
    now=time.time() if now is None else now
    previous=previous or {};old=previous.get('_raw',{});errors=[]
    value={'observed_at':int(now),'cpu_count':os.cpu_count() or 1,'cpu_percent':None,'cpu_steal_percent':None,'io_wait_percent':None,
           'memory_total_bytes':None,'memory_used_bytes':None,'memory_percent':None,'load':None,'disks':[],
           'network':{'interfaces':[],'rx_bytes_per_second':None,'tx_bytes_per_second':None,'packets_per_second':None,'drops_delta':None,'errors_delta':None},
           'conntrack_count':None,'conntrack_max':None,'tcp_established':None,'tcp_retransmit_percent':None,'alerts':[],'errors':errors}
    raw={'at':now}
    try:
        lines=text(root,'/proc/stat').splitlines();ticks=list(map(int,lines[0].split()[1:9]));boot=next(l for l in lines if l.startswith('btime ')).split()[1]
        raw.update(cpu=ticks,boot=boot)
        if old.get('boot')==boot and len(old.get('cpu',[]))==8:
            delta=[a-b for a,b in zip(ticks,old['cpu'])];total=sum(delta)
            if min(delta)>=0 and total>0:
                value.update(cpu_percent=round(100*(total-delta[3]-delta[4])/total,2),io_wait_percent=round(100*delta[4]/total,2),cpu_steal_percent=round(100*delta[7]/total,2))
    except (OSError,ValueError,IndexError,StopIteration):errors.append('CPU_UNAVAILABLE')
    elapsed=now-old.get('at',now);valid=raw.get('boot') is not None and raw.get('boot')==old.get('boot') and 0<elapsed<=120
    try:
        mem={l.split(':')[0]:int(l.split()[1])*1024 for l in text(root,'/proc/meminfo').splitlines() if ':' in l and len(l.split())>=2}
        total=mem['MemTotal'];available=mem['MemAvailable'];used=max(0,total-available)
        value.update(memory_total_bytes=total,memory_used_bytes=used,memory_percent=round(used*100/total,2))
    except (OSError,ValueError,KeyError,ZeroDivisionError):errors.append('MEMORY_UNAVAILABLE')
    try:value['load']=list(map(float,text(root,'/proc/loadavg').split()[:3]))
    except (OSError,ValueError):errors.append('LOAD_UNAVAILABLE')
    try:
        fs=os.statvfs(root);total=fs.f_blocks*fs.f_frsize;used=(fs.f_blocks-fs.f_bfree)*fs.f_frsize
        value['disks']=[{'mount':'/','total_bytes':total,'used_bytes':used,'available_bytes':fs.f_bavail*fs.f_frsize,'used_percent':round(used*100/total,2) if total else None,'inode_percent':round((fs.f_files-fs.f_ffree)*100/fs.f_files,2) if fs.f_files else None}]
    except OSError:errors.append('DISK_UNAVAILABLE')
    try:
        nics={}
        for line in text(root,'/proc/net/dev').splitlines()[2:]:
            name,values=line.split(':',1);name=name.strip()
            # Physical PCI/virtio VNICs only. Exclude lo, wg, bridges and veth;
            # counting a tunnel too would double-count the same traffic.
            if name=='lo' or not (root/'sys/class/net'/name/'device').exists():continue
            fields=list(map(int,values.split()));nics[name]=[fields[i] for i in (0,8,1,9,2,10,3,11)]
        raw['nics']=nics;value['network']['interfaces']=sorted(nics)
        if not nics:errors.append('PHYSICAL_NETWORK_UNAVAILABLE')
        if valid and nics and set(nics)==set(old.get('nics',{})):
            delta=[sum(nics[n][i]-old['nics'][n][i] for n in nics) for i in range(8)]
            if min(delta)>=0:value['network'].update(rx_bytes_per_second=delta[0]/elapsed,tx_bytes_per_second=delta[1]/elapsed,packets_per_second=(delta[2]+delta[3])/elapsed,errors_delta=delta[4]+delta[5],drops_delta=delta[6]+delta[7])
        speed=(value['network']['rx_bytes_per_second'] or 0)+(value['network']['tx_bytes_per_second'] or 0)
        raw['network_baseline']=speed if not valid else .1*speed+.9*old.get('network_baseline',speed)
        raw['samples']=old.get('samples',0)+1 if valid else 1
        if valid and old.get('samples',0)>=6 and speed>=1250000 and speed>4*max(1,old.get('network_baseline',speed)):
            value['alerts'].append({'code':'TRAFFIC_SURGE','severity':'warning','message':'物理网卡流量突增，请核对是否为正常传输。'})
    except (OSError,ValueError,IndexError,KeyError,TypeError):errors.append('NETWORK_UNAVAILABLE')
    for field,name in [('conntrack_count','nf_conntrack_count'),('conntrack_max','nf_conntrack_max')]:
        try:value[field]=int(text(root,'/proc/sys/net/netfilter/'+name).strip())
        except (OSError,ValueError):pass
    try:
        lines=text(root,'/proc/net/snmp').splitlines()
        for index in range(len(lines)-1):
            if lines[index].startswith('Tcp:') and lines[index+1].startswith('Tcp:'):
                tcp=dict(zip(lines[index].split()[1:],map(int,lines[index+1].split()[1:])));raw['tcp']=tcp;value['tcp_established']=tcp.get('CurrEstab')
                if valid and old.get('tcp'):
                    sent=tcp['OutSegs']-old['tcp']['OutSegs'];retry=tcp['RetransSegs']-old['tcp']['RetransSegs']
                    if sent>=100 and retry>=0:value['tcp_retransmit_percent']=round(retry*100/sent,2)
                break
    except (OSError,ValueError,KeyError,IndexError):pass
    def threshold(code,number,warning,critical,message):
        if number is not None and number>=warning:value['alerts'].append({'code':code,'severity':'critical' if number>=critical else 'warning','message':message})
    threshold('CPU_HIGH',value['cpu_percent'],90,97,'CPU 使用率偏高。')
    threshold('MEMORY_HIGH',value['memory_percent'],90,97,'可用内存偏低。')
    threshold('CPU_STEAL',value['cpu_steal_percent'],10,30,'虚拟 CPU 等待宿主机调度偏高。')
    if value['load']:threshold('LOAD_HIGH',value['load'][0]/value['cpu_count'],1.5,3,'系统运行队列负载偏高。')
    for disk in value['disks']:
        threshold('DISK_HIGH',disk['used_percent'],90,97,'系统磁盘空间偏低。');threshold('INODES_HIGH',disk['inode_percent'],90,97,'文件系统 inode 余量偏低。')
    if value['conntrack_max']:threshold('CONNTRACK_HIGH',(value['conntrack_count'] or 0)*100/value['conntrack_max'],80,95,'连接跟踪表接近容量上限。')
    threshold('TCP_RETRANSMITS',value['tcp_retransmit_percent'],10,30,'TCP 重传比例偏高，请核对线路质量。')
    if value['network']['drops_delta'] or value['network']['errors_delta']:value['alerts'].append({'code':'NETWORK_DROPS','severity':'warning','message':'物理网卡出现丢包或错误计数。'})
    if errors:value['alerts'].append({'code':'PARTIAL_SAMPLE','severity':'warning','message':'部分系统指标不可读取，未知值未按零处理。'})
    value['_raw']=raw
    return value


def public(value):return {k:v for k,v in value.items() if k!='_raw'}

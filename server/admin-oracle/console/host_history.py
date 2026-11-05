"""Bounded 35-day minute aggregates; missing observations stay missing."""
import math
from datetime import timedelta
from django.utils import timezone
from django.core.cache import cache
from .models import HostMetricMinute

FIELDS=('cpu','memory','disk','load','rx','tx')
WINDOWS={'hour':(3600,60),'day':(86400,900),'week':(604800,3600),'month':(2592000,21600)}

def values(health):
    network=health.get('network') or {};disk=(health.get('disks') or [{}])[0]
    result={'cpu':health.get('cpu_percent'),'memory':health.get('memory_percent'),'disk':disk.get('used_percent'),'load':(health.get('load') or [None])[0],'rx':network.get('rx_bytes_per_second'),'tx':network.get('tx_bytes_per_second')}
    return {k:v for k,v in result.items() if type(v) in (int,float) and math.isfinite(v) and 0<=v<=1e18}

def record(health,at):
    minute=at.replace(second=0,microsecond=0)
    row,_=HostMetricMinute.objects.get_or_create(at=minute,defaults={'aggregates':{}})
    for key,value in values(health).items():
        total,count=row.aggregates.get(key,[0,0]);row.aggregates[key]=[total+value,count+1]
    row.save(update_fields=['aggregates'])
    HostMetricMinute.objects.filter(at__lt=at-timedelta(days=35)).delete()

def series(window,now=None):
    use_cache=now is None
    if use_cache:
        cached=cache.get('host-history-v1:'+window)
        if cached is not None:return cached
    duration,step=WINDOWS[window];now=now or timezone.now();end=int(now.timestamp());start=end-duration
    first=start//step*step;groups={};samples=0
    for row in HostMetricMinute.objects.filter(at__gte=now-timedelta(seconds=duration),at__lte=now).order_by('at').iterator(chunk_size=512):
        bucket=int(row.at.timestamp())//step*step;group=groups.setdefault(bucket,{})
        for key in FIELDS:
            if key in row.aggregates:
                total,count=row.aggregates[key];old=group.get(key,[0,0]);group[key]=[old[0]+total,old[1]+count]
        samples+=1
    history=[]
    for at in range(first,end+1,step):
        group=groups.get(at,{})
        history.append({'at':at,**{key:group[key][0]/group[key][1] if key in group and group[key][1] else None for key in FIELDS}})
    earliest=HostMetricMinute.objects.order_by('at').values_list('at',flat=True).first()
    result={'window':window,'range_from':start,'range_to':end,'bucket_seconds':step,'recorded_from':int(earliest.timestamp()) if earliest else None,'observed_minutes':samples,'history':history}
    if use_cache:cache.set('host-history-v1:'+window,result,30)
    return result

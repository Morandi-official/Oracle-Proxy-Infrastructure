"""Real shared IPv4/IPv6 account bandwidth in disposable network namespaces only."""
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('account_qos',ROOT/'server/admin-oracle/control/qos.py')
qos=importlib.util.module_from_spec(spec);spec.loader.exec_module(qos)

def run(args,**kwargs):
    accepted=kwargs.pop('accepted',(0,))
    value=subprocess.run(args,capture_output=True,text=True,timeout=30,**kwargs)
    if value.returncode not in accepted:raise RuntimeError('COMMAND_FAILED '+repr(args)+' '+value.stderr[:1000])
    return value

def main():
    if not (os.geteuid()==0 and os.environ.get('ORACLE_ADMIN_DISPOSABLE_CI')=='1'):
        raise SystemExit('Disposable root network namespace required')
    name='opx-rate-'+uuid.uuid4().hex[:8];servers=[]
    try:
        run(['ip','netns','add',name]);run(['ip','-n',name,'link','set','lo','up'])
        run(['ip','link','add','wg0','type','veth','peer','name','rate-client'])
        run(['ip','link','set','rate-client','netns',name])
        for family,local,remote in (('4','10.250.0.1/24','10.250.0.2/24'),('6','fd42:250::1/64','fd42:250::2/64')):
            run(['ip','-'+family,'addr','add',local,'dev','wg0',*(['nodad'] if family=='6' else [])])
            run(['ip','-n',name,'-'+family,'addr','add',remote,'dev','rate-client',*(['nodad'] if family=='6' else [])])
        run(['ip','link','set','wg0','up']);run(['ip','-n',name,'link','set','rate-client','up'])
        for port in (5201,5202):
            servers.append(subprocess.Popen(['iperf3','-s','-p',str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        with tempfile.TemporaryDirectory() as tmp:
            controller=qos.Controller(run,Path(tmp),lambda:None)
            plan=[{'slot':1,'download_bps':4_000_000,'upload_bps':4_000_000,'addresses':['10.250.0.2','fd42:250::2']}]
            controller.apply(plan)
            def measure(reverse):
                def one(value):
                    address,port=value
                    args=['ip','netns','exec',name,'iperf3','-c',address,'-p',str(port),'-t','4','-J']+(['-R'] if reverse else [])
                    data=json.loads(run(args).stdout)
                    return data['end']['sum_received']['bits_per_second']
                with concurrent.futures.ThreadPoolExecutor(2) as pool:
                    return sum(pool.map(one,[('10.250.0.1',5201),('fd42:250::1',5202)]))
            for reverse,label in ((True,'DOWNLOAD'),(False,'UPLOAD')):
                rate=measure(reverse)
                assert 100_000<rate<6_500_000,(label,rate)
                print(f'ACTUAL_SHARED_DUALSTACK_{label}_CAP=PASS aggregate_bps={int(rate)}')
            controller.apply([])
            rate=measure(True);assert rate>8_000_000,rate
            print('ACTUAL_CLEAR_RATE_RESTORES_UNLIMITED=PASS')
            run(['tc','qdisc','add','dev','wg0','root','handle','991:','fq_codel'])
            try:controller.apply(plan)
            except ValueError as error:assert str(error)=='BANDWIDTH_FOREIGN_QDISC'
            else:raise AssertionError('Foreign qdisc replaced')
            value=json.loads(run(['tc','-j','qdisc','show','dev','wg0']).stdout)
            assert any(q.get('handle')=='991:' for q in value)
            print('ACTUAL_FOREIGN_QDISC_REFUSED_AND_PRESERVED=PASS')
    finally:
        for process in servers:process.terminate();process.wait(timeout=5)
        run(['ip','link','del','wg0'],accepted=(0,1))
        run(['ip','netns','del',name],accepted=(0,1))

if __name__=='__main__':main()

"""Render a reviewed endpoint change from non-secret GitHub Environment variables.

No OCI calls, SSH, DNS changes or IP deletion are performed here.
"""
import argparse
import copy
import json
import os
import re
from pathlib import Path
from endpoint_catalog import ROOT,load,schema

VARIABLES={
 'primary':('PROXY_PRIMARY_IPV4','PROXY_PRIMARY_PRIVATE_IPV4'),
 'backup':('PROXY_BACKUP_IPV4','PROXY_BACKUP_PRIVATE_IPV4'),
}

def propose(current,variables,mode,confirmed):
    schema.validate(current)
    if mode not in ('prepare','cutover'):raise ValueError('INVALID_ENDPOINT_MODE')
    if not confirmed:raise ValueError('CONFIRM_ACTUAL_OCI_BINDINGS_FIRST')
    value=copy.deepcopy(current)
    for role,(public,private) in VARIABLES.items():
        if not variables.get(public) or not variables.get(private):raise ValueError('MISSING_'+public+'_OR_'+private)
        value[role]={'public_ipv4':variables[public].strip(),'private_ipv4':variables[private].strip()}
    value['active']=variables.get('PROXY_ACTIVE_INGRESS','primary').strip() or 'primary'
    old_rows=[current['primary'],current['backup']]+current['legacy']
    new_publics={value[r]['public_ipv4'] for r in VARIABLES}
    value['legacy']=[copy.deepcopy(row) for row in old_rows if row['public_ipv4'] not in new_publics]
    if mode=='prepare':
        for role in VARIABLES:
            for old in old_rows:
                if old['public_ipv4']==value[role]['public_ipv4'] and old['private_ipv4']!=value[role]['private_ipv4']:raise ValueError('BINDING_MOVE_REQUIRES_CUTOVER')
    else:
        if any(value[r]['public_ipv4']!=current[r]['public_ipv4'] for r in VARIABLES):raise ValueError('PREPARE_NEW_PUBLIC_IPS_BEFORE_CUTOVER')
        if value['primary']['private_ipv4']!='10.0.0.6':raise ValueError('CUTOVER_PRIMARY_PRIVATE_MUST_BE_10_0_0_6')
        # Complete only an explicit permutation of already recorded bindings.
        moves={value[r]['private_ipv4']:current[r]['private_ipv4'] for r in VARIABLES if value[r]['private_ipv4']!=current[r]['private_ipv4']}
        occupied={value[r]['private_ipv4'] for r in VARIABLES}
        for row in value['legacy']:
            address=row['private_ipv4'];seen=set()
            while address in occupied:
                if address in seen or address not in moves:raise ValueError('AMBIGUOUS_PRIVATE_BINDING_SWAP')
                seen.add(address);address=moves[address]
            row['private_ipv4']=address
        rows=[value['primary'],value['backup']]+value['legacy']
        if {r['private_ipv4'] for r in rows}!={r['private_ipv4'] for r in old_rows}:raise ValueError('CUTOVER_MUST_PRESERVE_PRIVATE_ADDRESS_SET')
    rows=[value['primary'],value['backup']]+value['legacy']
    default=[r['public_ipv4'] for r in rows if r['private_ipv4']=='10.0.0.6']
    if len(default)!=1:raise ValueError('ONE_DEFAULT_PRIVATE_BINDING_REQUIRED')
    paired=set(current['egress_ipv4'])=={current[r]['public_ipv4'] for r in VARIABLES}
    value['egress_ipv4']=([value[r]['public_ipv4'] for r in VARIABLES] if paired else
                          list(dict.fromkeys(default+([value['primary']['public_ipv4']] if mode=='prepare' else []))))
    schema.validate(value)
    if value==current:return None
    value['revision']=current['revision']+1
    return schema.validate(value)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--mode',choices=['prepare','cutover'],required=True);parser.add_argument('--confirmed-bindings',action='store_true');args=parser.parse_args()
    current=load();next_value=propose(current,os.environ,args.mode,args.confirmed_bindings)
    if next_value is None:print('ENDPOINT_SETTINGS=NO_CHANGES');return
    (ROOT/'ops/network/endpoints.json').write_text(json.dumps(next_value,indent=2)+'\n')
    (ROOT/'ops/oracle-project/request.json').write_text(json.dumps({'operation':'preflight','request_id':'endpoint-catalog-apply'})+'\n')
    print('ENDPOINT_SETTINGS=PROPOSAL_ONLY; revision='+str(next_value['revision']))
    print('EXPECTED_PRIMARY='+next_value['primary']['public_ipv4']+' -> '+next_value['primary']['private_ipv4'])
    print('EXPECTED_BACKUP='+next_value['backup']['public_ipv4']+' -> '+next_value['backup']['private_ipv4'])
    print('EXPECTED_IPV4_EXIT='+','.join(next_value['egress_ipv4']))

if __name__=='__main__':
    try:main()
    except (ValueError,TypeError,KeyError) as error:
        code=str(error)
        print('ENDPOINT_SETTINGS_ERROR='+(code if re.fullmatch('[A-Z0-9_]{1,100}',code) else 'INVALID_ENDPOINT_SETTINGS'))
        raise SystemExit(2) from None

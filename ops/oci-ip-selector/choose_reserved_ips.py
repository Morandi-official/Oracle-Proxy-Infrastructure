#!/usr/bin/env python3
"""Manual choice of up to four held OCI IP candidates, with a ten-slot persistent cap."""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import time
import uuid

spec=importlib.util.spec_from_file_location('choice_common',Path(__file__).with_name('pick_reserved_ip.py'))
api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
ORIGINAL_IPS={'152.67.156.100','141.147.78.44'}
LIMIT=10
HELD_LIMIT=4


def owned(row,entry,compartment,original):
    return (isinstance(row,dict) and row.get('id')==entry.get('id') and
            row.get('id') not in original and row.get('ip-address')==entry.get('ip') and
            row.get('ip-address') not in ORIGINAL_IPS and
            str(row.get('id','')).startswith('ocid1.publicip.oc1.uk-london-1.') and
            row.get('display-name')==entry.get('name') and row.get('compartment-id')==compartment and
            row.get('lifetime')=='RESERVED' and row.get('lifecycle-state')=='AVAILABLE' and
            not api.binding(row) and row.get('freeform-tags',{}).get('choice-run')==entry.get('run'))


def held(state):return [x for x in state['attempts'] if x.get('status')=='HELD_UNBOUND']


def verify(state,rows,compartment):
    original=state['original'];current=api.snapshot(rows)
    if any(current.get(k)!=v for k,v in original.items()):raise api.Stop('ORIGINAL_IP_OR_BINDING_CHANGED')
    expected=set(original)
    by_id={r['id']:r for r in rows}
    for entry in held(state):
        if not owned(by_id.get(entry['id']),entry,compartment,original):raise api.Stop('HELD_CANDIDATE_CHANGED')
        expected.add(entry['id'])
    if set(current)!=expected:raise api.Stop('UNEXPECTED_RESOURCE_RECONCILE_FIRST')
    if any(x['status'] not in ('HELD_UNBOUND','ABSENCE_VERIFIED','REJECTED') for x in state['attempts']):
        raise api.Stop('UNRESOLVED_INTENT_RECONCILE_FIRST')


def load(path,compartment):
    if path.is_symlink():raise api.Stop('JOURNAL_SYMLINK_REFUSED')
    info=path.stat()
    if info.st_uid!=os.getuid() or info.st_mode&0o077 or info.st_size>262144:raise api.Stop('UNTRUSTED_JOURNAL')
    state=json.loads(path.read_text())
    if (state.get('schema')!=1 or state.get('region')!=api.REGION or state.get('compartment')!=compartment or
        state.get('limit')!=LIMIT or state.get('held_limit')!=HELD_LIMIT or
        not isinstance(state.get('attempts'),list) or len(state['attempts'])>LIMIT or
        any(x.get('number')!=n for n,x in enumerate(state['attempts'],1))):raise api.Stop('JOURNAL_SCOPE_OR_COUNT_INVALID')
    return state


def process(compartment,path,create=False,discard=()):
    fd=os.open(path.with_name('run.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise api.Stop('RUN_ALREADY_ACTIVE') from None
        rows=api.inventory(compartment)
        if path.exists():state=load(path,compartment)
        else:
            if discard:raise api.Stop('NO_EXISTING_CHOICE_JOURNAL')
            if {r['ip-address'] for r in rows}!=ORIGINAL_IPS or len(rows)!=2:
                raise api.Stop('REMOVE_EXTRA_IPS_AND_VERIFY_ORIGINAL_TWO_FIRST')
            state={'schema':1,'region':api.REGION,'compartment':compartment,'limit':LIMIT,'held_limit':HELD_LIMIT,
                   'run':uuid.uuid4().hex,'original':api.snapshot(rows),'attempts':[],'status':'ready','next_create_at':0}
            api.save(path,state)
        verify(state,rows,compartment)
        if discard:
            targets=[x for x in held(state) if x['number'] in discard]
            if len(targets)!=len(set(discard)):raise api.Stop('DISCARD_MUST_SELECT_EXISTING_HELD_NUMBERS')
            for entry in targets:
                row=api.cli(['get','--public-ip-id',entry['id']]).get('data')
                if not owned(row,entry,compartment,state['original']):raise api.Stop('DELETE_OWNER_OR_BINDING_REFUSED')
                entry['status']='delete_intent';api.save(path,state)
                try:api.cli(['delete','--public-ip-id',entry['id'],'--force'])
                except api.CliError as e:
                    if e.status!=404:raise
                try:api.cli(['get','--public-ip-id',entry['id']])
                except api.CliError as e:
                    if e.status!=404:raise
                else:raise api.Stop('DELETE_STILL_READABLE')
                after=api.inventory(compartment)
                if any(r['id']==entry['id'] for r in after):raise api.Stop('DELETE_NOT_VERIFIED_IN_INVENTORY')
                entry['status']='ABSENCE_VERIFIED';state['next_create_at']=time.time()+60
                verify(state,after,compartment);api.save(path,state)
        if create:
            q=api.quota(compartment)
            count=min(HELD_LIMIT-len(held(state)),LIMIT-len(state['attempts']),int(q['available']))
            if count<=0:
                print('NO_NEW_CREATION: candidate slots, attempt budget or quota unavailable',flush=True)
            for _ in range(count):
                wait=max(0,state['next_create_at']-time.time())
                if wait:
                    print('WAIT_SECONDS='+str(round(wait)),flush=True);time.sleep(wait)
                verify(state,api.inventory(compartment),compartment)
                q=api.quota(compartment)
                if q['available']<1:raise api.Stop('QUOTA_UNAVAILABLE_NO_CREATE')
                n=len(state['attempts'])+1
                entry={'number':n,'run':state['run'],'name':'udp-choice-'+state['run'][:8]+'-'+str(n),
                       'status':'creation_intent','client_request_id':str(uuid.uuid4())}
                state['attempts'].append(entry);state['next_create_at']=time.time()+60;api.save(path,state)
                try:
                    response=api.cli(['create','--compartment-id',compartment,'--lifetime','RESERVED',
                                      '--display-name',entry['name'],'--freeform-tags',json.dumps({'choice-run':state['run']})],
                                     request_id=entry['client_request_id'])
                except api.CliError as e:
                    state['error_details']=e.details
                    if e.code in ('LimitExceeded','TooManyRequests'):
                        entry['status']='REJECTED'
                        state['next_create_at']=time.time()+900
                    raise
                raw=path.with_name('create-'+str(n)+'.json');api.save(raw,response)
                row=response.get('data',{})
                entry.update(id=row.get('id'),ip=row.get('ip-address'),created_at=row.get('time-created'),raw_response=raw.name)
                api.save(path,state)
                if not owned(row,entry,compartment,state['original']):raise api.Stop('CREATION_NOT_OWNED_OR_UNBOUND')
                actual=api.cli(['get','--public-ip-id',entry['id']]).get('data')
                if not owned(actual,entry,compartment,state['original']):raise api.Stop('LIVE_CANDIDATE_CHECK_FAILED')
                entry['status']='HELD_UNBOUND';entry['matches_previous_pattern']=api.matches(entry['ip'])
                api.save(path,state);print(json.dumps(entry,ensure_ascii=False),flush=True)
            verify(state,api.inventory(compartment),compartment)
        state['status']='awaiting_choice' if held(state) else 'ready'
        api.save(path,state)
        return state
    except BaseException as e:
        if 'state' in locals():
            state['status']='STOPPED_REVIEW_JOURNAL';state['error']=str(e) if isinstance(e,api.Stop) else type(e).__name__
            if isinstance(e,api.CliError):state['error_details']=e.details
            api.save(path,state)
        raise
    finally:os.close(fd)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compartment-id',required=True)
    group=p.add_mutually_exclusive_group()
    group.add_argument('--create-batch',action='store_true')
    group.add_argument('--discard',help='Comma-separated held candidate numbers selected for deletion.')
    args=p.parse_args()
    directory=Path.home()/'.proxy-ip-choice-20261108';path=directory/'state.json'
    if not (args.create_batch or args.discard):
        print(json.dumps({'scope':'READ_ONLY','inventory':api.snapshot(api.inventory(args.compartment_id)),
                          'choice_state':load(path,args.compartment_id) if path.exists() else None},ensure_ascii=False,indent=2));return
    if directory.is_symlink():raise api.Stop('JOURNAL_DIRECTORY_SYMLINK_REFUSED')
    directory.mkdir(mode=0o700,exist_ok=True)
    info=directory.stat()
    if info.st_uid!=os.getuid() or info.st_mode&0o077:raise api.Stop('PRIVATE_OWNED_DIRECTORY_REQUIRED')
    discard=tuple(int(x) for x in args.discard.split(',')) if args.discard else ()
    state=process(args.compartment_id,path,args.create_batch,discard)
    print(json.dumps({'status':state['status'],'attempts_used':len(state['attempts']),
                      'remaining_attempts':LIMIT-len(state['attempts']),'candidates':held(state),
                      'journal':str(path)},ensure_ascii=False,indent=2))


if __name__=='__main__':
    try:main()
    except Exception as e:
        print('STOPPED='+(str(e) if isinstance(e,api.Stop) else type(e).__name__),flush=True)
        print('Keep ~/.proxy-ip-choice-20261108/state.json for review; do not erase or reset the budget.')
        raise SystemExit(2) from None

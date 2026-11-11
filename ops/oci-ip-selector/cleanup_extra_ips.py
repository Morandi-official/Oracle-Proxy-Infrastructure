#!/usr/bin/env python3
"""Remove only the two explicitly authorized surplus IPs after host retirement."""
import argparse
import importlib.util
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('cleanup_common',Path(__file__).with_name('pick_reserved_ip.py'))
api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
VNIC='ocid1.vnic.oc1.uk-london-1.abwgiljtvinh2xd5rknwxycmpniiwzaekj6fub5y27lmefjmfieikxmzauxq'
PRIVATE157='ocid1.privateip.oc1.uk-london-1.aaaaaaaa67vtzkagn5xwaxoknl4keq5xrzpbmowm2dofn663sgm36gekz36q'
ORIGINAL={
 'ocid1.publicip.oc1.uk-london-1.amaaaaaaiqqyrziawvfnx2n3olbsecxbhxgrwzgga6zqkswzrbofnzs2hzra':('152.67.156.100','ocid1.privateip.oc1.uk-london-1.abwgiljticameqdeyir55yeaxuukkfiiounogxvwr3f265fb6i7h6qh2ivsq'),
 'ocid1.publicip.oc1.uk-london-1.amaaaaaaiqqyrziauygaylfx42wpp6g7cljpowaeidq3yuotirvsszj6gjba':('141.147.78.44','ocid1.privateip.oc1.uk-london-1.aaaaaaaauvnqt4jqk4dm6m2u62csyl3wikm4ju2yotzip26qnyuumgpjxrga')}
EXTRAS={
 'ocid1.publicip.oc1.uk-london-1.amaaaaaaiqqyrziatui6x5utw3pxeetmdbft3ftiqlfl6vt5otpgwbk557ea':('130.162.169.253',None),
 'ocid1.publicip.oc1.uk-london-1.amaaaaaaiqqyrziazab3yhdlppg4g2dyiblntlq72ce7a4m34t6ny5qh7uta':('79.72.85.11',PRIVATE157)}


def check(rows):
 by_id={r['id']:r for r in rows}
 if set(by_id)-set(ORIGINAL)-set(EXTRAS):raise api.Stop('UNEXPECTED_RESOURCE_NO_DELETE')
 for key,(ip,private) in ORIGINAL.items():
  row=by_id.get(key,{})
  if row.get('ip-address')!=ip or api.binding(row)!=private or row.get('lifecycle-state')!='ASSIGNED':
   raise api.Stop('RESTORED_ORIGINAL_BINDINGS_REQUIRED')
 for key,(ip,private) in EXTRAS.items():
  if key not in by_id:continue
  row=by_id[key]
  if (row.get('ip-address')!=ip or row.get('lifetime')!='RESERVED' or
      api.binding(row) not in (None,private) or row.get('lifecycle-state') not in ('AVAILABLE','ASSIGNED')):
   raise api.Stop('EXACT_EXTRA_RESOURCE_NOT_VERIFIED')
 return by_id


def private157():
 try:row=api.invoke(['network','private-ip','get','--private-ip-id',PRIVATE157]).get('data',{})
 except api.CliError as e:
  if e.status==404:return None
  raise
 if (row.get('id')!=PRIVATE157 or row.get('ip-address')!='10.0.0.157' or
     row.get('vnic-id')!=VNIC or row.get('is-primary') is not False):
  raise api.Stop('EXACT_NONPRIMARY_PRIVATE157_REQUIRED')
 return row


def execute(compartment,apply=False):
 rows=api.inventory(compartment);current=check(rows);private=private157()
 if not apply:return {'scope':'READ_ONLY','inventory':api.snapshot(rows),'temporary_private_present':private is not None}
 # Server-side alias/timer retirement must already have been verified by the owner.
 for key,(ip,_) in EXTRAS.items():
  current=check(api.inventory(compartment))
  if key not in current:continue
  actual=api.cli(['get','--public-ip-id',key]).get('data',{})
  if actual!=current[key]:raise api.Stop('RESOURCE_CHANGED_REVIEW_BEFORE_DELETE')
  try:api.cli(['delete','--public-ip-id',key,'--force'])
  except api.CliError as e:
   if e.status!=404:raise
  try:api.cli(['get','--public-ip-id',key])
  except api.CliError as e:
   if e.status!=404:raise
  else:raise api.Stop('PUBLIC_DELETE_NOT_VERIFIED')
  after=check(api.inventory(compartment))
  if key in after:raise api.Stop('PUBLIC_STILL_IN_INVENTORY')
  print('PUBLIC_ABSENCE_VERIFIED='+ip,flush=True)
 if set(check(api.inventory(compartment)))!=set(ORIGINAL):raise api.Stop('EXTRA_PUBLIC_IP_STILL_PRESENT')
 if private157() is not None:
  api.invoke(['network','private-ip','delete','--private-ip-id',PRIVATE157,'--force'])
  if private157() is not None:raise api.Stop('PRIVATE157_DELETE_NOT_VERIFIED')
 private_rows=api.invoke(['network','private-ip','list','--vnic-id',VNIC,'--all']).get('data')
 if not isinstance(private_rows,list) or any(r.get('id')==PRIVATE157 or r.get('ip-address')=='10.0.0.157' for r in private_rows):
  raise api.Stop('PRIVATE157_ABSENCE_IN_COMPLETE_LIST_REQUIRED')
 if not {'10.0.0.6','10.0.0.10'} <= {r.get('ip-address') for r in private_rows}:
  raise api.Stop('ORIGINAL_PRIVATE_ADDRESSES_REQUIRED')
 final=check(api.inventory(compartment))
 if set(final)!=set(ORIGINAL):raise api.Stop('FINAL_TWO_ORIGINAL_IPS_REQUIRED')
 return {'cleaned':True,'remaining':api.snapshot(list(final.values())),'temporary_private_removed':True}


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--compartment-id',required=True)
 p.add_argument('--apply',action='store_true')
 p.add_argument('--host-retirement-verified',action='store_true')
 args=p.parse_args()
 if args.apply and not args.host_retirement_verified:raise api.Stop('VERIFY_SERVER_ALIAS_AND_TIMER_RETIREMENT_FIRST')
 print(json.dumps(execute(args.compartment_id,args.apply),ensure_ascii=False,indent=2))


if __name__=='__main__':
 try:main()
 except Exception as e:
  print('STOPPED='+(str(e) if isinstance(e,api.Stop) else type(e).__name__))
  raise SystemExit(2) from None

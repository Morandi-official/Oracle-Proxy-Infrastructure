"""Inspect the exact diagnostic flow log and associated filter without mutation."""
import ipaddress
import json
import re

GROUP='ocid1.loggroup.oc1.uk-london-1.amaaaaaaiqqyrzia6rtmdlprq5i6m6zoj7e6lxkausrct3otalalz7zajlfq'
LOG='ocid1.log.oc1.uk-london-1.amaaaaaaiqqyrziag6tnmkfoxsns7bshwj5xiod6tnzsgw5ebuihlozzlrmq'
VNIC='ocid1.vnic.oc1.uk-london-1.abwgiljtvinh2xd5rknwxycmpniiwzaekj6fub5y27lmefjmfieikxmzauxq'
ADDRESSES=('10.0.0.6','10.0.0.10','10.0.0.220','10.0.0.246')


def safe_error(error):
    code=getattr(error,'code',None)
    return {'status':'OCI_ERROR','http_status':getattr(error,'status',None),
            'code':code if isinstance(code,str) and re.fullmatch(r'[A-Za-z0-9_]{1,80}',code) else type(error).__name__}


def cidr(value):
    if not value:
        return {'any':True,'known_addresses':list(ADDRESSES)}
    try:
        network=ipaddress.ip_network(value,strict=False)
    except ValueError:
        return {'any':False,'known_addresses':[],'unrecognized':True}
    return {'any':network.prefixlen==0,'family':network.version,
            'known_addresses':[a for a in ADDRESSES if ipaddress.ip_address(a) in network]}


def span(value):
    return [value.min,value.max] if value is not None else None


def summarize(rule):
    udp=rule.udp_options
    return {'priority':rule.priority,'enabled':rule.is_enabled,'action':rule.rule_action,
            'direction':getattr(rule,'traffic_direction',None),'protocol':rule.protocol,'flow_log_type':rule.flow_log_type,
            'sampling_interval':rule.sampling_rate,
            'source':cidr(rule.source_cidr),'destination':cidr(rule.destination_cidr),
            'udp_source_ports':span(udp.source_port_range) if udp else None,
            'udp_destination_ports':span(udp.destination_port_range) if udp else None}


def observe():
    import oci
    result={}
    config={'region':'uk-london-1'}
    retry=oci.retry.NoneRetryStrategy()
    try:
        signer=oci.auth.signers.InstancePrincipalsSecurityTokenSigner(retry_strategy=retry,federation_client_retry_strategy=retry)
    except Exception as error:
        return {'identity':safe_error(error)}
    target_filter=None
    try:
        management=oci.logging.LoggingManagementClient(config,signer=signer,timeout=(4,9),retry_strategy=retry)
        log=management.get_log(GROUP,LOG).data
        source=log.configuration.source
        resource=source.resource
        result['log']={'status':'OBSERVED','is_enabled':log.is_enabled,'state':log.lifecycle_state,
                       'category':source.category,'service':source.service,'on_expected_vnic':resource==VNIC}
        target_filter=(source.parameters or {}).get('capture_filter')
        if not isinstance(target_filter,str) or not re.fullmatch(r'ocid1\.capturefilter\.oc1\.[a-z0-9.-]{6,160}',target_filter):
            target_filter=None
    except Exception as error:
        result['log']=safe_error(error)
    network=oci.core.VirtualNetworkClient(config,signer=signer,timeout=(4,9),retry_strategy=retry)
    link=target_filter is not None
    if target_filter is None:
        try:
            listed=network.list_capture_filters(signer.tenancy_id,display_name='udp-path-focused',limit=30)
            hits=[item for item in listed.data if item.display_name=='udp-path-focused']
            if len(hits)==1 and not listed.headers.get('opc-next-page'):
                target_filter=hits[0].id
            else:
                result['filter']={'status':'LINK_UNVERIFIED','exact_name_matches':len(hits)}
        except Exception as error:
            result['filter']=safe_error(error)
    if target_filter:
        try:
            observed=network.get_capture_filter(target_filter).data
            rules=sorted(observed.flow_log_capture_filter_rules or [],key=lambda item:item.priority or 0)
            result['filter']={'status':'OBSERVED','name_matches_udp_path_focused':observed.display_name=='udp-path-focused',
                              'verified_log_link':link,'rule_count':len(rules),'rules':[summarize(rule) for rule in rules[:10]]}
        except Exception as error:
            result['filter']=safe_error(error)
    return result


if __name__=='__main__':
    print(json.dumps(observe(),sort_keys=True))

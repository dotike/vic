#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Base python library for VIC tooling.

Currently provides:
    Compound boto wrappers for common use and challenging AWS API requests.
    Also provides tools for various common tasks throughout codebase.

Testing:
    Functional tests for each function in this library exist with the source
    code in 'tests/', one script per function.  The tests can be run using
    'vic test-aws -L', see 'vic test-aws -h' for more info.

TODO: figure out how to raise UserWarning for every AWS call if we are using the root AWS account.
'''
# @depends: None
__version__ = '0.1'
__author__ = 'Isaac (.ike) Levy <ike@blackskyresearch.net>'


import os
import sys
import re
from fnmatch import translate
import boto3
import time
import ipcalc
import socket
from collections import OrderedDict
import base64

def aws_whoami():
    '''
    Simple self-id in the spirit of whoami(1).

    Args: None.

    Returns: short login name for current AWS authenticated user.
    '''
    try:
        iam = boto3.resource('iam')
        whoami = iam.CurrentUser()
        return str(whoami.user_name).rstrip()
    except Exception as err:
        raise type(err)('aws_whoami() error: {}'.format(err))

def aws_lastlogin():
    '''
    Simple self-id in the spirit of login(1).

    Args: None.

    Returns:
    '''
    try:
        iam = boto3.resource('iam')
        whoami = iam.CurrentUser()
        msg = "Last AWS login for {0}: {1}".format(
            whoami.user_name,
            whoami.password_last_used.isoformat(),
        )
        return msg
    except Exception as err:
        raise type(err)('aws_whoami() error: {}'.format(err))

def aws_tags_dict(taglist):
    '''
    Convenience function to relieve fumbling around with AWS tag lists.
    Given a list of AWS tags, (common to most AWS object types), converts
    the list into a dict keyed by tag:Key.

    Args: taglsit - list of dicts from AWS API tag.

    Returns: dict of Key, Value pairs.  If supplied tag list contains
             no values, returns an empty dict.
    '''
    returndict = {}
    try:
        # we don't want to iterate on string input, (python clumsy types bit)
        if isinstance(taglist, basestring) or not isinstance(taglist, (list, tuple)):
            raise ValueError("'taglist' should be a list of dicts, got: '{}'".format(
                taglist))
        for tagd in taglist:
            returndict[tagd['Key']] = tagd['Value']
        return returndict
    except Exception as err:
        raise type(err)('aws_tags_dict(): {}'.format(err))

def wallclock():
    '''
    Prints the current time in RFC 3339 / ISO 8601 format.

    Ags: none.

    Returns: string.

    NOTE: due to the myriad of TZ handling edges in time.localtime and
    time.timezone, plus complications where Python strftime strays from
    POSIX standards, this function exec's to use the system date.
    '''
    try:
        sysdate = str(os.popen("date +%Y-%m-%dT%H:%M:%S%z").read())
        return "{0}{1}{2}".format(sysdate[:22], ":", sysdate[22:]).rstrip()
    except Exception as err:
        raise type(err)('wallclock() error: {}'.format(err))

def afail():
    '''
    Used to reliably exit when -a (or $a) is thrown out of context.
    This is all quite out of context.

    Args: None.

    Returns: Prints message and exit 87.
    '''
    print >> sys.stderr, str(base64.b64decode("Tm8gQWxnb2wgNjggaGVyZS4="))
    sys.exit(87)

def fetch_vic_meta(vic_id, region=None):
    '''
    Given a vic name or vpc id, return the basic identifier metadata
    about a given vic.

    Args:
        vic_id (str), vic name or vpc id.
        region (str), optional aws region to limit query

    Returns: Flat dict of values derived from AWS tags for VIC VPC.
    '''
    returnmeta = {}
    _found = False
    _next_token = ''
    _tagpile = {}
    try:
        if region:
            regions = [region]
        else:
            regions = region_resolver()

        for oneregion in regions:
            set_region(region=oneregion)
            endresponse = False

            while endresponse == False and _found == False:
                try:
                    if _next_token:
                        vpc_client = boto3.client('ec2', region_name=oneregion)
                        vpc_response = vpc_client.describe_tags(
                            DryRun=False,
                            Filters=[
                                {
                                    'Name': 'resource-id',
                                    'Values': [vic_id,]
                                },
                            ],
                            MaxResults=1000,
                            NextToken=_next_token,

                        )
                    else:
                        vpc_client = boto3.client('ec2', region_name=oneregion)
                        vpc_response = vpc_client.describe_tags(
                            DryRun=False,
                            Filters=[
                                {
                                    'Name': 'resource-id',
                                    'Values': [vic_id,]
                                },
                            ],
                            MaxResults=1000,
                        )
                except Exception as err:
                    raise ValueError(err)
                if 'NextToken' in vpc_response:
                    _next_token = vpc_response['NextToken']
                else:
                    endresponse = True
                for _each_tag, _each_val in aws_tags_dict(vpc_response['Tags']).iteritems():
                    _tagpile[_each_tag] = _each_val
                if len(_tagpile) > 0:
                    _found = True

            for tagn, tagv in _tagpile.iteritems():
                if tagn == 'Name':
                    returnmeta['vic_name'] = tagv
                    returnmeta['region'] = name_to_region(tagv)
                else:
                    returnmeta[tagn] = tagv
            if _found:
                break

        set_region()
        return returnmeta
    except Exception as err:
        raise type(err)('fetch_vic_meta() error: {}'.format(err))


def validate_vic_id(vic_id):
    '''
    Validates a vic id with AWS, which can be a striing name for either:
       - a VPC ID, unique to AWS enviornment
       - the VPC tag "Name", which should match

    Attempts to make the fewest calls possible to AWS.

    Args: string, vic name or vpc id.

    Returns: most cases, returns string, the vpc id, confirmed in AWS.
             In the event of *multiple* VPC's with the same tag 'Name',
             returns a list of stirngs- which consumer programs can either
             lazily error out over, or, handle in context.
             Empty tag:Name strings throw an error, for sanity.

    >>> validate_vic_id('vpc-05bb1e62')
    'vpc-05bb1e62'

    >>> validate_vic_id('hot_latte')
    'vpc-05bb1e62'

    >>> validate_vic_id('') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> validate_vic_id('asdf') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    EnvironmentError

    >>> validate_vic_id()
    Traceback (most recent call last):
    TypeError: validate_vic_id() takes exactly 1 argument (0 given)

    >>> validate_vic_id(['foo', 'bar']) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    EnvironmentError
    '''
    try:
        # isolate region from dns,
        region = name_to_region(vic_id)
        if region:
            set_region(region)

        client = boto3.client('ec2')
        if not vic_id == '':
             try:
                 # straight for the answer,
                  response = client.describe_vpcs(
                             DryRun=False,
                             VpcIds=[vic_id]
                             )['Vpcs'][0]['VpcId']

             except Exception as err1:
                 # filter query to keep it light payload,
                 try:
                     vlist = client.describe_vpcs(
                             DryRun=False,
                             Filters=[{'Name': 'tag:Name', 'Values': [vic_id]},],
                             )['Vpcs']
                 # now uplack that result and straight for the answer again,
                     if len(vlist) == 1:
                 # this is the common case
                         response = vlist[0]['VpcId'] 
                 # if that didn't work, do we have any results?
                     elif not vlist:
                         msg = "No 'vic_id' in AWS with tag:Name or Object ID '{}'".format(vic_id)
                         raise ValueError(msg)
                 # finally, we must have too many results, (rare and broken case),
                     else:
                         response = []
                         for avpc in vlist:
                             response.append(avpc['VpcId'])

                 except Exception as err2:
                     emsg = "AWS or boto error: {0}: {1}".format(err1, err2)
                     raise EnvironmentError(emsg)
        else:
            vmsg = "validate_vic_id() given '{}', does not handle empty string vic names.".format(vic_id)
            raise ValueError(vmsg)

        if region:
            set_region()
        return response

    except Exception as err:
        raise type(err)('validate_vic_id(): {}'.format(err))

def validate_create_id(create_session_uid_or_vic_id, vics_list=None):
    '''
    Given the "vic create session id" UUID, return associated vic name.
    Given a vic name or VPC id, return the "vic create session id" value.

    Args:
        'create_session_uid_or_vic_id' string, required expecting one of
        two possible values:
        - vic create session id, the UUID used/tagged during VIC creation.
        - the vic_id (or VPC id)

       vics_list - dict, optional - output from list_vics(), an expensive
       call which allows users who will be iteratively valididating create
       id's make their list_vics() call once, at the beginning of their
       operation.

    Returns:
        If vic creation id given, vic name is returned.
        If vic name is given, vic creation id is returned.
        If result does not exist, an empty string is returned.
    '''
    if not vics_list:
        vics_list = list_vics()

    for pvpc, pdict in vics_list.iteritems():
        if pdict['TagSane']['vic_create_session_id'] == create_session_uid_or_vic_id:
            sresponse = pdict['TagSane']['Name'] 
            break
        elif pdict['TagSane']['Name'] == create_session_uid_or_vic_id:
            sresponse = pdict['TagSane']['vic_create_session_id']
            break

    return sresponse

def list_key_pairs(vic_id='', region=''):
    '''
    List AWS key pairs globally, per region, or constrained to a given vic
    name or id.
    SSH key pairs are a region-wide resource, and may cross VIC boundaries.

    Args:
        vic_id - string, name or instance id for a given VIC.
                 When supplied, only key names beginning with 'vic_id' will
                 be returned.
                 (When supplied, also constrains to a given region.)
        region - string, an aws region available to our account.
                 (Ignoreed when vic_id is supplied.)

    Returns: dict with key and metadata, keyed by AWS key name.
       (keys are one AWS resource which *DOES NOT* have an AWS object
       ID/UUID, nor do they have tagging capabilities.)

    Bugs: this was implemented while under the impression that AWS/boto
        filter calls were not behaving uniformly, (for other AWS products/
        services).  Therefore, we do all filtering the expensive way here-
        fetching fat payloads, and filtering here, for reliability.
    '''
    regions = []
    key_return = {}
    shortcircuit = False
    try:
        if vic_id:
            shortcircuit = True
            try: # if we're handed a vic name,
                _shortreg = name_to_region(vic_id)
                upsert_list(regions, _shortreg)
            except Exception as err: # if given a vic-id, we must regions till we hit it,
                raise type(err)('validate_vic_id(): {}'.format(err))
                regions = region_resolver(allregions=True)
        elif region:
            upsert_list(regions, region)
        else:
            regions = region_resolver(allregions=True)

        for _region in regions:
            try:
                keyclient = boto3.client('ec2', region_name=_region)
                keyresponse = keyclient.describe_key_pairs(
                    DryRun=False
                )
                for keymeta in keyresponse['KeyPairs']:
                    if keymeta['KeyName'].endswith(vic_id):
                        keymeta['region'] = _region
                        keymeta['vic_id'] = vic_id
                        key_return[keymeta['KeyName']] = keymeta
            except Exception as err:
                raise ValueError(err)

        return key_return
    except Exception as err:
        raise type(err)('validate_vic_id(): {}'.format(err))

def list_global_vpcs():
    '''
    Lists AWS VPC's across all global regions for a given account.
    (boto, Amazon, why is this not just a thing?)

    Args: None.

    Returns:
        Dict of VPC attributes, keyed by VPC ID.

    When requesting VPC's for a specific region, simply use boto describe_vpcs().
    '''
    vpc_pile = []
    regions = region_resolver(allregions=True)
    try:
        for oneregion in regions:
            set_region(region=oneregion)
            vpcs = {}
            ec2 = boto3.client('ec2', region_name=oneregion)
            try:
                vpcs = ec2.describe_vpcs()
                for _eachvpc in vpcs['Vpcs']:
                    _eachvpc['region'] = oneregion
                    vpc_pile.append(_eachvpc)
            except Exception as err:
                raise ValueError(err)
                #pass # careful there...
        set_region()

        # Build dict of relevant VPCs, keyed by ID, even if zero items,
        keyed_vpcs = {}
        for _vpc in vpc_pile:
            keyed_vpcs[_vpc['VpcId']] = _vpc
        return keyed_vpcs

    except Exception as err:
        raise type(err)('list_global_vpcs(): {}'.format(err))


def list_vics(vic_id=''):
    '''
    List VPC's associated with our account, across all AWS regions, in a manner
    which caters to vic management.

    Args:
        If no args given, list all VPCs in the AWS account.
        This includes all VPC's, including unnamed via vic names.

        vic_id (str): Optional, single vic name or VPC ID to filter/return.

    Returns:
        Dict of VPC attributes, keyed by VPC ID.
        If vic_id is given, return the same dict format, with just that VIC.

    >>> is_a_dict = list_vics().keys()

    >>> is_a_dict = list_vics('hot_latte').keys()

    >>> len(list_vics('vpc-05bb1e62').keys()) <= 1
    True

    >>> list_vics('foobar') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> list_vics('') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> list_vics(['foo','bar']) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError
    '''
    vpc_pile = []
    # only real VIC VPC's have them,
    genuine_vic = [{'Name': 'tag-key', 'Values': ['vic_create_session_id']}]
    try:
        region_short_circuit = name_to_region(vic_id) 
        if region_short_circuit:
            regions = [region_short_circuit]
        else:
            regions = region_resolver(allregions=True)

        if vic_id:
            vpc_id = validate_vic_id(vic_id)
            for oneregion in regions:
                set_region(region=oneregion)
                vpcs = {}
                try:
                    ec2 = boto3.client('ec2', region_name=oneregion)
                    vpcs = ec2.describe_vpcs(
                                            Filters=genuine_vic,
                                            DryRun=False,
                                            VpcIds=[vpc_id],
                                            )['Vpcs']
                except Exception:
                    pass  # careful there...
                for _eachvpc in vpcs:
                    _eachvpc['region'] = oneregion
                    vpc_pile.append(_eachvpc)

        else:
            for oneregion in regions:
                set_region(region=oneregion)
                vpcs = {} # necessary since we pass on failed calls,
                try:
                    ec2 = boto3.client('ec2', region_name=oneregion)
                    vpcs = ec2.describe_vpcs(DryRun=False, Filters=genuine_vic)['Vpcs']
                    for _eachvpc in vpcs:
                        _eachvpc['region'] = oneregion
                        vpc_pile.append(_eachvpc)
                except Exception:
                    pass # careful there...

        set_region()

        if not vpc_pile and vic_id is not '': 
            msg = "No VIC in with tag:Name or Object ID '{}'".format(vic_id)
            raise ValueError(msg)

        # Build dict of relevant VPCs, keyed by ID, even if zero items,
        keyed_vpcs = {}
        for _vpc in vpc_pile:
            keyed_vpcs[_vpc['VpcId']] = _vpc
            keyed_vpcs[_vpc['VpcId']]['TagSane'] = \
                aws_tags_dict(keyed_vpcs[_vpc['VpcId']]['Tags'])

        return keyed_vpcs

    except Exception as err:
        raise type(err)('list_vics(): {}'.format(err))

def list_route_tables(vic_id='', route_table_ids=[], region=None):
    '''
    Fetch a list of route tables associated with a given VIC,
    providing the vpc-id they are associated with.

    Args:
        vic_id, string, optional vic id or name
        route_table_ids, list, optional list of explicit route tables
        region, string, optional AWS region available to our account

    Returns: dict of route tables and metadata, keyed by route_table_ids.
        Special attention paid to ammend 'Main' route table association
        status.

    Bugs:
        Returns which encompass all regions are not supported, this can
        be changed.  Also, stripping values by Filters are buggy in
        AWS API end, so proceed with caution if using them.

    TODO:
       modify return of list_vics to include associated route tables
    '''
    routes_return = {}
    try:
        try:
            _dud = os.environ['AWS_DEFAULT_REGION']
        except:
            _dud = ''
        if not region:
            region = _dud

        try:
            rclient = boto3.client('ec2', region_name=region)
            rresponse = rclient.describe_route_tables(
                DryRun=False,
                RouteTableIds=route_table_ids,
            )
        except Exception as err:
            raise ValueError(err)

        if vic_id:
            try:
                vic_valid= validate_vic_id(vic_id)
            except:
                vic_valid = vic_id
            for oneroute in rresponse['RouteTables']:
                if oneroute['VpcId'] == vic_valid:
                    oneroute['TagSane'] = aws_tags_dict(oneroute['Tags'])
                    routes_return[oneroute['RouteTableId']] = oneroute
        else:
            for oneroute in rresponse['RouteTables']:
                oneroute['TagSane'] = aws_tags_dict(oneroute['Tags'])
                routes_return[oneroute['RouteTableId']] = oneroute

        # this is gonna seem a little crazy, but, this lets us find out if
        # a route table is listed as a 'Main' route table simpler in client code.
        for r_id, r_meta in routes_return.iteritems():
            for assoc in r_meta['Associations']:
                if 'Main' in assoc:
                    if assoc['Main'] == True:
                        routes_return[r_id]['Main'] = assoc['Main']
                    else:
                        if 'Main' in routes_return[r_id]:
                            if routes_return[r_id]['Main'] != True:
                                routes_return[r_id]['Main'] = False
            if not 'Main' in routes_return[r_id]:
                routes_return[r_id]['Main'] = False

        return routes_return
    except Exception as err:
        raise type(err)('list_route_tables(): {}'.format(err))


def list_network_acls(acl_id=None, vic_id=None, region=None):
    '''
    List network acls, able to constrain to vic_id, or a single acl.

    Args:
        None, returns all IGW objects for the default region.
        acl_id, str, return only the named igw_id.
        vic_id, str, single VPC ID or Name, to fetch associated igw.
        region, str, optional AWS region valid for our account.
           Notice: this argument is disregarded if vic_id is given,
           instead using the region AWS says the vic is in.

    Returns: dict of acls and metadata, keyed by acl_id.
      If no acl's exist to be returned for the call, empty dict returned.

    BUGS:
      Currently operates in a single region.  Should be upgraded to
      operate across all regions, (imagine simple security audit tools
      for the future).
      Due to AWS API instability with 'Filters', at the time this was
      written, this does all filtering locally after fetching a big
      list from a given region.  This really sucks, but we need this
      call to perform it's job with rock-solid reliability, payload size
      be damned.

    TODO:
      # modify return of list_vics to include associated network_acls
      # create feature flag to return acl attached to a given subnet id
    '''
    acl_id_list = []
    acl_return = {}
    try:
        if vic_id:
            _region = name_to_region(vic_id)
            _vic_id = validate_vic_id(vic_id)
        elif region:
            _region = region
            _vic_id=''
        else:
            try:
                _region = os.environ['AWS_DEFAULT_REGION']
            except:
                _region = ''
            _vic_id=''
        if acl_id:
            upsert_list(acl_id_list, acl_id)

        try:
            aclclient = boto3.client('ec2', region_name=_region)
            aclresponse = aclclient.describe_network_acls(
                DryRun=False,
                NetworkAclIds=acl_id_list,
            )
        except Exception as err:
            raise ValueError(err)

        for raw_acl in aclresponse['NetworkAcls']:
            if _vic_id:
                if raw_acl['VpcId'] == _vic_id:
                    raw_acl['TagSane'] = aws_tags_dict(raw_acl['Tags'])
                    acl_return[raw_acl['NetworkAclId']] = raw_acl
            else:
                raw_acl['TagSane'] = aws_tags_dict(raw_acl['Tags'])
                acl_return[raw_acl['NetworkAclId']] = raw_acl

        return acl_return
    except Exception as err:
        raise type(err)('list_network_acls(): {}'.format(err))


def list_igw(igw_id=None, vic_id=None, region=None):
    '''
    Lists igw objects in several common contexts.

    Args:
        None, returns all IGW objects for our account.
        igw_id, str, return only the named igw_id.
        vic_id, str, single VPC ID or Name, to fetch associated igw.
        region, str, optional AWS region valid for our account

    Returns:
       dict keyed by igw object id, in every case.
       Returns empty dict if no IGW objects exist.
       If igw_id and vic_id are both specified, we start
       with the smallest resolution object first, igw_id.
       We do not then try the vic_id.

    Bugs:
       Region is constrained to either supplied value, or,
       whatever region is set in ENV set 'AWS_DEFAULT_REGION',
       at the time this function is called.

    >>> len(list_igw().keys()) >=1
    True

    >>> print list_igw(igw_id='igw-bf7de0db')['igw-bf7de0db']['Attachments'][0]['VpcId']
    vpc-05bb1e62

    >>> list_igw(vic_id='hot_latte').keys()
    ['igw-bf7de0db']

    >>> print list_igw(igw_id='igw-bf7de0db', vic_id='hot_latte').keys()
    ['igw-bf7de0db']

    >>> print list_igw(igw_id='igw-asdf', vic_id='hot_latte') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    TypeError

    >>> print list_igw(igw_id=['foo', 'bar']) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    TypeError

    >>> print list_igw(vic_id=['foo', 'bar']) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    EnvironmentError

    >>> print list_igw(None, None, None, None) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    TypeError

    http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.describe_internet_gateways
    '''
    keyed_igws = {}
    filters = []
    igw_req = []

    try:

        if vic_id:
            try:
                vic_valid= validate_vic_id(vic_id)
            except:
                vic_valid = vic_id
        # AWS API seems to be totally disregarding this filter value,
        # noticed Mon Jun 18 17:53:48 EDT 2018
        if vic_id is not None:
            pl = {'Name': 'attachment.vpc-id',
                  'Values': [vic_valid] }
            upsert_list(filters, pl)

        if igw_id is not None:
            upsert_list(igw_req, igw_id)

        try:
            _dud = os.environ['AWS_DEFAULT_REGION']
        except:
            _dud = ''
        if not region:
            region = _dud

        try:
            client = boto3.client('ec2', region_name=region)
            response = client.describe_internet_gateways(
                Filters=filters,
                DryRun=False,
                InternetGatewayIds=igw_req,
            )
        except TypeError:
            list_igw(igw_id=None, vic_id=vic_id)

        for gw in response['InternetGateways']:
            keyed_igws[gw['InternetGatewayId']] = gw

    except Exception as err:
        raise type(err)('list_igw(): {}'.format(err))

    return keyed_igws

def name_to_region(name):
    '''
    Returns an AWS geographic region for a given 'vic_id.tld'
    Flexible enough to return instantiated region when given,
      - vic_id.tld
      - *.vic_id.tld

    Args: string, name to look up.

    Returns: AWS region string name.
    If none, returns empty string.

    Depends on AWS 'region.vic_id.tld' TXT record which should contain
    only one string response, the AWS region.
    '''
    try:
        return r53_lookup(name='region.{}'.format(name), dns_type='TXT')[0]
    except IndexError or ValueError as err1:
        for nametry in domain_walkback(name):
            try:
                return r53_lookup(name='region.{}'.format(nametry), dns_type='TXT')[0]
            except:
                failfinal = nametry
        if failfinal:
            return ''
    except Exception as err:
        raise type(err)('name_to_region(): {}'.format(err))

def list_logical_subnets(network):
    '''
    Return VPC subnet metadata list for a given logical subnet.
    Used because unified VPC subnets span multiple physical AZ's.

    Args: network - string, a logical subnet name, (e.g. wan.vic_id.tld)

    Returns: Dict of logical subnet metadata, keyed by subnet name.
    If network or logical_map does not exist, raise appropriate error.
    '''
    logical_return = {}
    failmsg = "Region cannot be derived from dns records, VIC may not exist, cannot list subnets belonging to: '{}'.".format(
        network)
    try:
        # set region for this call
        region = name_to_region(network)
        if not region:
            raise ValueError(failmsg)
        set_region(region)

        try:
            logical_map = r53_lookup(name='logical_map.{}'.format(network), dns_type='TXT')
        except Exception as err:
            raise ValueError("{0} : {1}".format(failmsg, err))

        for netstr in logical_map:
            netpair = netstr.split(' ', 1)
            logical_return[netpair[0]] = netpair[1]

        # reset our region to runtime original,
        set_region()

        return logical_return

    except Exception as err:
        raise type(err)('list_logical_subnets(): {}'.format(err))

def list_physical_subnets(vicname_or_logicalname, show_metadata=False):
    '''
    Given a vic name or logical network name, return information about the
    physical VPC subnets, keyed by subnet id.

    Args:
          vicname_or_logicalname, str, either valid vic name or logical network name.
            e.g.: 'hot_latte.vic' or 'wan.hot_latte.vic'.  In this way, resolution of
            the name supplied determines resolution of the response.

          show_metadata, Boolean, enables return of subnet metadata for convenience,
            yet is quite slow with additional AWS queries required.

    Returns: dict of physical VPC subnets, keyed by subnet id.
    '''
    map_dict = {}
    subnets_return = {}
    try:
        # set region for subnet calls
        region = name_to_region(vicname_or_logicalname)
        if not region:
            raise ValueError("Region cannot be derived from dns records, cannot proceed with '{}'.".format(
                vicname_or_logicalname))
        set_region(region)

        failfinal = ''
        physical_map = None
        try:
            physical_map = r53_lookup(name='physical_map.{}'.format(vicname_or_logicalname), dns_type='TXT')
        # Need to walk back the domain in list_logical_networks
        except IndexError or ValueError as err1:
            for nametry in domain_walkback(vicname_or_logicalname):
                # short circuit once we find it,
                if not physical_map:
                    physical_map = r53_lookup(name='physical_map.{}'.format(nametry), dns_type='TXT')
        if failfinal and not physical_map:
            raise ValueError(
                "'physical_map cannot be derived from dns records for '{0}'.".format(
                    vicname_or_logicalname))

        for netstr in physical_map:
            netpair = netstr.split(' ', 1)
            map_dict[netpair[0]] = netpair[1]

        # resolver,
        for subname in map_dict.keys():
            if subname.endswith(vicname_or_logicalname):
                subnets_return[subname] = map_dict[subname]

        if not subnets_return:
            raise ValueError("Cannot find named subnets for '{}'.".format(
                vicname_or_logicalname))

        for queryname in subnets_return.keys():
            namednet = subnets_return[queryname]
            try:
                subid = validate_subnet_id(queryname)
                if show_metadata:
                    subq = list_vic_subnets(subnet_id=subid, sregion=region)
                    # we only get one in this query, but man py clumsy here,
                    subdetail = subq[next(iter(subq))]
                    try:
                        subdetail['TagSane'] = aws_tags_dict(subdetail['Tags'])
                    except:
                       subdetail['TagSane'] = {}
                else:
                    subdetail = {}
            except:
                subid = ''
                subdetail = {}

            subnets_return[queryname] = {}
            subnets_return[queryname]['physical_net'] = namednet
            subnets_return[queryname]['subnet_id'] = subid
            subnets_return[queryname]['aws_metadata'] = subdetail

        # reset our region to runtime original,
        set_region()
        return subnets_return

    except Exception as err:
        raise type(err)('list_physical_subnets(): {}'.format(err))

def validate_subnet_id(subnet_id):
    '''
    Validates a subnet id with AWS, which can be a striing name for either:
       - a Subnet ID, unique to AWS enviornment
       - the Subnet tag "Name", which should match

    Attempts to make the fewest calls possible to AWS.

    Args: string, subnet name or subnet id.

    Returns: most cases, returns string, the subnet id, confirmed in AWS.
             In the event of *multiple* subnets with the same tag 'Name',
             returns a list of strings- which consumer programs can either
             lazily error out over, or, handle in context.

             If name or id does not exist, an empty string is returned.
             Errors only thrown for program or network/api errors.
    '''
    filters = []
    subnet_req = []
    try:
        upsert_list(subnet_req, subnet_id)

        client = boto3.client('ec2')
        if not subnet_id == '':
            try:
                # straight for the answer,
                response = client.describe_subnets(
                    Filters=filters,
                    SubnetIds = subnet_req,
                    DryRun=False)['Subnets'][0]['SubnetId']
# TODO: something in here is broken in a subtle way,
# "invalid arg: workspot failure: local variable 'response' referenced before assignment"
            except Exception as err1:
                try:
                    slist = client.describe_subnets(
                            DryRun=False,
                            Filters=[{'Name': 'tag:Name', 'Values': [subnet_id]},],
                            )['Subnets']
                # now uplack that result and straight for the answer again,
                    if len(slist) == 1:
                # this is the common case
                        response = slist[0]['SubnetId']
                # if that didn't work, do we have any results?
                    elif not slist:
                        msg = "No 'subnet_id' in AWS with tag:Name or Object ID '{}'".format(subnet_id)
                # finally, we must have too many results, (rare and broken case),
                    else:
                        response = []
                        for asubnet in slist:
                            response.append(asubnet['SubnetId'])

                except Exception as err2:
                    emsg = "AWS or boto error: {0}: {1}".format(err1, err2)
                    raise EnvironmentError(emsg)

        else:
            vmsg = "validate_subnet_id() given '{}', does not handle empty string subnet names.".format(vic_id)
            raise ValueError(vmsg)

    except Exception as err:
        raise type(err)('validate_subnet_id(): {}'.format(err))

    return response

def list_global_subnets():
    '''
    Lists AWS VPC's across all global regions for a given account.
    (boto, Amazon, why is this not just a thing?)

    Args: None.

    Returns:
        Dict of VPC subnet attributes, keyed by subnet ID.

    When requesting VPC's for a specific region, simply use boto describe_subnets().
    '''
    subnet_pile = []
    regions = region_resolver(allregions=True)
    try:
        for oneregion in regions:
            set_region(region=oneregion)
            subnets = {}
            ec2 = boto3.client('ec2', region_name=oneregion)
            try:
                subnets = ec2.describe_subnets(DryRun=False)
                #prettyPrint(subnets)

                for _eachsub in subnets['Subnets']:
                    _eachsub['region'] = oneregion
                    subnet_pile.append(_eachsub)
            except Exception as err:
                raise ValueError(err)
                #pass # careful there...
        set_region()

        # Build dict of relevant VPCs, keyed by ID, even if zero items,
        keyed_subs = {}
        for _sub in subnet_pile:
            keyed_subs[_sub['SubnetId']] = _sub
        return keyed_subs

    except Exception as err:
        raise type(err)('list_global_subnets(): {}'.format(err))

def list_vpc_subnets(vic_id):
    '''
    Simple interface to return all VPC subnets, given a vic name or VPC ID.
    Works according to AWS relationships, so not specific to vic metadata- helpful
    for creation problems or debugging.

    Args: vic_id (str): single VPC ID or Name, fetches only subnets it contains.

    Returns: dict of subnet attributes, keyed by subnet ID,
             global region aware.
    '''
    keyed_subnets = {}
    try:
        region = name_to_region(vic_id)
        set_region(region)
        vpc_id = validate_vic_id(vic_id)

        try:
            sub_ec2 = boto3.client('ec2', region_name=region)
            live_subnets = sub_ec2.describe_subnets(
                DryRun=False,
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_id,]
                    },
                ],

            )
            #prettyPrint(live_subnets['Subnets'])
            for subnet in live_subnets['Subnets']:
                subnet['region'] = region
                keyed_subnets[subnet['SubnetId']] = subnet

        except Exception as err:
            raise ValueError(err)

        set_region()
        return keyed_subnets
    except Exception as err:
        raise type(err)('list_vpc_subnets(): {}'.format(err))

def list_vic_subnets(vic_id='', subnet_id='', sregion='', allregions=False):
    '''
    Lists subnets for a given VPC, (plural).

    Args (all optional):

        vic_id (str): single VPC ID or Name, fetches only subnets it contains.

        subnet_id: single vpc subnet name or object id to return.

        sregion: shortcut region, attempts to search this region first, dramatically
                 reducing the time this call can take to return.

        allregion: boolean, force checking all regions, useful to expose
                   possible conflicts, absolutely checks all regions.

    Returns:
        dict of subnet attributes, keyed by subnet ID.
        If both id args are supplied, the lower resolution request wins,
        and the single subnet id is returned.  If that Id does not exist,
        the vic_id is not also tried.
        When called without any arguments, the query is quite slow, as
        it looks for vic subnets across all global AWS regions.

    Bugs:
        The AWS API, and the console, often return profoundly different results.
        For example: when deleting subnets, the api may return all subnets
        for a given VPC ID, as "'State': 'available'", even though they have
        been deleted and the VPC itself has been deleted.
        No idea to whom, or how, to report this bug to AWS.  (perhaps they
        respond to tweets?)

    >>> list_vic_subnets('vpc-05bb1e62').keys()[0].startswith('subnet-')
    True

    >>> list_vic_subnets(subnet_id='subnet-88f478d3').keys()[0].startswith('subnet-')
    True

    >>> list_vic_subnets(vic_id='hot_latte').keys()[0].startswith('subnet-')
    True

    >>> list_vic_subnets('hot_latte').keys()[0].startswith('subnet-')
    True

    >>> list_vic_subnets() # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> list_vic_subnets('asdf') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    EnvironmentError

    >>> list_vic_subnets('') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> list_vic_subnets(['foo', 'bar']) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    EnvironmentError

    >>> list_vic_subnets(vic_id=['foo', 'bar']) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    EnvironmentError

    >>> list_vic_subnets(subnet_id='') # doctest: +IGNORE_EXCEPTION_DETAIL
    ValueError(ClientError(u"An error occurred (InvalidSubnetID.NotFound) when calling the DescribeSubnets operation: The subnet ID '' does not exist",),)

    http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.describe_subnets
    '''
    keyed_subnets = {}
    filters = []
    subnet_req = []
    regions = []
    shortcircuit = False
    try:
        upsert_list(filters,
            {'Name': 'tag-key', 'Values': ['vic_create_session_id']})
        if sregion:
            regions = region_resolver(startwith=[sregion], allregions=allregions)
        elif vic_id:
            regions = [name_to_region(vic_id)]
            upsert_list(filters,
                {'Name': 'vpc-id',
                 'Values': [validate_vic_id(vic_id)]})
        # ideal case is that we strip down to a single region based on input, but,
        if not regions:
            regions = region_resolver(allregions=True)

        if subnet_id:
            valid_id = validate_subnet_id(subnet_id)
            upsert_list(subnet_req, valid_id)
            shortcircuit = True

        # holy cow this is nondeterministically SLOW if all regions,
        if vic_id:
            for oneregion in regions:
                set_region(oneregion)
                try:
                    ec2 = boto3.client('ec2', region_name=oneregion)
                    # we can describe_subnets() in one query per region,
                    subnets = ec2.describe_subnets(
                        Filters=filters,
                        SubnetIds = subnet_req,
                        DryRun=False)
                except Exception as err:
                    raise ValueError(err)

                for subnet in subnets['Subnets']:
                    subnet['region'] = oneregion
                    keyed_subnets[subnet['SubnetId']] = subnet
        else:
            for oneregion in regions:
                set_region(oneregion)
                try:
                    ec2 = boto3.client('ec2', region_name=oneregion)
                    # we can describe_subnets() in one query per region,
                    subnets = ec2.describe_subnets(
                        Filters=filters,
                        SubnetIds = subnet_req,
                        DryRun=False)
                except Exception:
                    pass # careful here...

                for subnet in subnets['Subnets']:
                    subnet['region'] = oneregion
                    keyed_subnets[subnet['SubnetId']] = subnet
                if shortcircuit and len(keyed_subnets) > 0:
                    break
        set_region()

    except Exception as err:
        raise type(err)('list_vic_subnets(): {}'.format(err))

    return keyed_subnets

def get_paginated_reservations(filters=[], instance_ids=[]):
    '''
    DEPRECATED - this doesn't appear to return all possible AWS instance
    classes.

    Given a filter or list of instance IDs, return a list of EC2 reservations,
    accounting for paginated results. The AWS API returns, at most, only 1000
    rows.

    Args:
        filters (list): Optional filters to apply to the search
        instance_ids (list): optional list of instance IDs (strings) to
            limit the search to

    Returns:
        list of EC2 reservation dicts (as returned by boto3)
    '''
    from warnings import warn
    warn("EC2 instance list may not yet contain all instance types.",
          DeprecationWarning)

    all_reservations = []
    done = False
    next_token = ''

    try:
        ec2 = boto3.client('ec2')
        while not done:
            try:
                some_reservations = ec2.describe_instances(Filters=filters,
                                                           InstanceIds=instance_ids,
                                                           NextToken=next_token)
            except Exception as err:
                raise EnvironmentError('boto3 call: {}'.format(err))

            for reservation in some_reservations['Reservations']:
                all_reservations.append(reservation)

            if 'NextToken' in some_reservations.keys():
                next_token = some_reservations['NextToken']
            else:
                done = True

    except Exception as err:
        raise type(err)('get_paginated_reservations(): {}'.format(err))

    return all_reservations

def list_nat_amis(region='', configpath=None):
    '''
    Returns a list of avaiable NAT Instance 'AMI's for a given region.

    Args:
      configpath - string path to vic config file.
      Defaults to '<myhier>/etc/vic.conf' if not supplied.

    Returns: A dict keyed by ami-id, each describing a NAT Instance AMI.

    Further documentation:
    https://docs.aws.amazon.com/vpc/latest/userguide/VPC_NAT_Instance.html
    https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-comparison.html
    '''
    regions = []
    nat_ami_return = {}
    try:
        vic_config = vics_loadconfig()
        if region:
            upsert_list(regions, region)
        else:
            regions = region_resolver(allregions=True)

        for _region in regions:
            try:
                natamiclient = boto3.client('ec2', region_name=_region)
                natamiresponse = natamiclient.describe_images(
                    Filters=[
                        {
                            'Name': 'description',
                            'Values': [
                                vic_config['nat_ami_default_search_description'],
                            ]
                        },
                    ],
                    DryRun=False
                )
                for each_ami in natamiresponse['Images']:
                    if each_ami['OwnerId'] == vic_config['nat_ami_default_search_owner_id']:
                        each_ami['region'] = _region
                        nat_ami_return[each_ami['ImageId']] = each_ami

            except Exception as err:
                raise ValueError(err)

        return nat_ami_return
    except Exception as err:
        raise type(err)('list_nat_amis() error: {}'.format(err))


def list_default_amis(region='', configpath=None):
    '''
    Returns a list of avaiable AMI's, based on our default image in vic config.

    Args:
      configpath - string path to vic config file.
      Defaults to '<myhier>/etc/vic.conf' if not supplied.

    Returns: A dict keyed by ami-id, each describing an AMI.
    '''
    regions = []
    ami_return = {}
    try:
        vic_config = vics_loadconfig()
        if region:
            upsert_list(regions, region)
        else:
            regions = region_resolver(allregions=True)

        for _region in regions:
            try:
                amiclient = boto3.client('ec2', region_name=_region)
                amiresponse = amiclient.describe_images(
                    Filters=[
                        {
                            'Name': 'description',
                            'Values': [
                                vic_config['ami_default_search_description'],
                            ]
                        },
                    ],
                    DryRun=False
                )
                for each_ami in amiresponse['Images']:
                    if each_ami['OwnerId'] == vic_config['ami_default_search_owner_id']:
                        each_ami['region'] = _region
                        ami_return[each_ami['ImageId']] = each_ami

            except Exception as err:
                raise ValueError(err)

        return ami_return
    except Exception as err:
        raise type(err)('list_default_amis() error: {}'.format(err))

def list_ssh_pub_keys(region='', vic_or_net_name=''):
    '''
    List ssh public keys available.
    (Public keys are bound to a given region.)

    Args: (one of the following is required)

      region - str, a region available to our account.

      vic_or_net_name - str, either a vic name, a logical network, or
        a physical subnet.  e.g.:
            + decaf_crema.vic
            + core.decaf_crema.vic
            + us-west-1b.core.decaf_crema.vic

    Returns: dict of public keys metadata, keyed by AWS 'name'.
             AWS ssh key pairs do not have AWS id's, and AWS treats
             their name as unique for a given region.
    '''
    key_return = {}
    _region = ''
    try:

        if region:
            _region = region

        if vic_or_net_name:
            namelist = vic_or_net_name.split('.')
            vic_name = "{0}.{1}".format(namelist[-2], namelist[-1])
            _region_from_name = name_to_region(vic_or_net_name)
            if _region and _region != _region_from_name:
                raise ValueError(
                   "Arguements conflict, vic_or_net_name is not in our region: '{0}' '{1}'".format(
                       region, vic_or_net_name))
            else:
                _region = _region_from_name
        if not region and not vic_or_net_name:
            smsg = "Missing required arg, requires 'region' or 'vic_or_net_name', got: '{0}' '{1}'".format(
                region, vic_or_net_name)
            raise ValueError(smsg)

        try:
            sgclient = boto3.client('ec2', region_name=_region)
            sgresponse = sgclient.describe_key_pairs(
                DryRun=False
            ) # look ma', no pagination!
        except Exception as err:
            raise ValueError(err)

        for keydict in sgresponse['KeyPairs']:
            key_return[keydict['KeyName']] = keydict
            key_return[keydict['KeyName']]['region'] = region

        return key_return
    except Exception as err:
        raise type(err)('list_ssh_pub_keys() error: {}'.format(err))


def list_vic_security_groups(vic_or_net_name=''):
    '''
    List security groups available to a given VIC.
    Security groups are bound to a VPC instance.

    Args: vic_or_net_name - string, named vic, or logical network,
          or physical subnet.  e.g.:
            + decaf_crema.vic
            + core.decaf_crema.vic
            + us-west-1b.core.decaf_crema.vic

    Returns: dict of security groups metadata, keyed by AWS sg id.
    '''
    sg_return = {}
    try:

        if vic_or_net_name:
            namelist = vic_or_net_name.split('.')
            vic_name = "{0}.{1}".format(namelist[-2], namelist[-1])
            region = name_to_region(vic_or_net_name)
            vic_id = validate_vic_id(vic_name)
        else:
            smsg = "Missing required arg, requires one string  name for either vic name, logical net, or physical subnet- but got: '{}'".format(
                vic_or_net_name)
            raise ValueError(smsg)

        sgclient = boto3.client('ec2', region_name=region)
        next_token = ''
        while True: # pagination meh
            try:
                sgresponse = sgclient.describe_security_groups(
                    Filters=[
                        {
                            'Name': 'vpc-id',
                            'Values': [vic_id,]
                        },
                    ],
                    DryRun=False,
                    NextToken=next_token,
                    MaxResults=100
                )
            except Exception as err:
                raise ValueError(err)
            for sg_dict in sgresponse['SecurityGroups']:
                if sg_dict['VpcId'] == vic_id:
                # intentional belt and suspenders, AWS API Filters are observed as flaky
                    try:
                        if sg_dict['Tags']:
                            tag_sane = aws_tags_dict(sg_dict['Tags'])
                        else:
                            tag_sane = {}
                    except:
                        tag_sane = {}
                    sg_return[sg_dict['GroupId']] = sg_dict
                    sg_return[sg_dict['GroupId']]['TagSane'] = tag_sane
                    sg_return[sg_dict['GroupId']]['region'] = region
                    sg_return[sg_dict['GroupId']]['vic_name'] = vic_name

            try:
                next_token = sgresponse['NextToken']
            except KeyError:
                break

        return sg_return
    except Exception as err:
        raise type(err)('list_default_amis() error: {}'.format(err))

def list_available_instance_types(region='', vic_or_net_name=''):
    '''
    List available instance types.
    Instance types are bound to a given region.
    '''
    # README: https://forums.aws.amazon.com/thread.jspa?threadID=87859
    print 'TODO workspot list_instance_types()'


def list_vic_instances(vic_name='', phys_subnet='', logical_net='',):
    '''
    Lists AWS instances, in a specific VIC.
    Explicitly does not return cross-VIC or cross-region responses,
    for safe use in VIC-wide operations like 'destroy'.

    Intended to include all instance types- Svic, On-Demand, and
    Scheduled/Reserved instances.

    Instances returned represent all of the available AWS types,
    https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-purchasing-options.html

    Args:
        One of these arguments is required.  If multiple arguments are supplied,
        The arg with the finest resolution wins, (e.g. less instances in a physical
        subnet than in logical networks).

        vic_name - string, Filter instances by VIC name or VPC ID.  Returns
                   instances which may be Classic, VPC, Svic, Reserved, whatever.

        phys_subnet - string, Filter instances by subnet name.

        logical_net - string, filter instances by logical network name.

    Returns: dict keyed by instance id, containing vic-enhanced AWS metadata.
    If no instances exist, an empty dict is returned.
    '''
    keyed_instances = {}
    subnets_to_search = []
    try:
        klist = "vic_name={0}, logical_net={1}, phys_subnet={2}".format(vic_name, logical_net, phys_subnet)
        kmsg = "Missing required arg, requires one of [vic_name, logical_net, phys_subnet] got: {}".format(
            klist)
        if phys_subnet:
            tld = phys_subnet.split('.')[-1]
            region = name_to_region(phys_subnet)
            network_meta=list_physical_subnets(vicname_or_logicalname=phys_subnet, show_metadata=True)
        elif logical_net:
            tld = logical_net.split('.')[-1]
            region = name_to_region(logical_net)
            network_meta=list_physical_subnets(vicname_or_logicalname=logical_net, show_metadata=True)
        elif vic_name:
            tld = vic_name.split('.')[-1]
            network_meta=list_physical_subnets(vicname_or_logicalname=vic_name, show_metadata=True)
            region = name_to_region(vic_name)
        else:
            raise ValueError(kmsg)

        if not network_meta: # short circuit, we have no subnets to search.
            return keyed_instances

        for sub_name, sub_meta in network_meta.iteritems():
            if not vic_name:
                vic_name = "{0}.{1}".format(sub_meta['aws_metadata']['TagSane']['vic_name'], tld)
            upsert_list(subnets_to_search, sub_meta['subnet_id'])
        if not subnets_to_search:
            subnets_to_search = ['']

        vic_class = r53_lookup(name="class.{}".format(vic_name), dns_type='TXT')[0]

        try:
            insclient = boto3.client('ec2', region_name=region)
            next_token = ''
            while True: # pagination meh
                try:
                    insresponse = insclient.describe_instances(
                            NextToken=next_token,
                            Filters=[
                                {
                                    'Name': 'subnet-id',
                                    'Values': subnets_to_search
                                },
                            ],

                    )
                except Exception as err:
                    raise ValueError(err)

                for classicwrap in insresponse['Reservations']:
                    reservation_wrapper = {}
                    # pack all 'Reservatinos' related data so we have everything,
                    _instaces_list = classicwrap.pop('Instances')
                    for res_key, res_meta in classicwrap.iteritems():
                        if res_key is not 'Instances':
                            reservation_wrapper[res_key] = res_meta
                    for insdict in _instaces_list:
                        # append VIC specific metadata,
                        insdict['region'] = region
                        insdict['vic_name'] = vic_name
                        insdict['vic_class'] = vic_class
                        try:
                            insdict['TagSane'] = aws_tags_dict(insdict['Tags'])
                        except:
                            insdict['TagSane'] = {}
                        # append reservation wrapper metadata intact`,
                        insdict['reservation_wrapper'] = reservation_wrapper

                        for net_key, net_meta in network_meta.iteritems():
                            if net_meta['subnet_id'] == insdict['SubnetId']:
                                insdict['physical_subnet_name'] = \
                                    net_meta['aws_metadata']['TagSane']['Name']
                                insdict['logical_network_name'] = \
                                    net_meta['aws_metadata']['TagSane']['logical_name']

                        keyed_instances[insdict['InstanceId']] = insdict
                try:
                    next_token = insresponse['NextToken']
                except KeyError:
                    break

        except Exception as err:
            raise ValueError(err)

        return keyed_instances
    except Exception as err:
        raise type(err)('list_vic_instances(): {}'.format(err))

    return keyed_instances

def tld_to_zone_id(zone_string=None):
    '''
    Because boto3 is a terrible library.  Absolute design failure, in fact.
    Fetches usable domain 'hostedzone' ID when given a domain name string.

     https://github.com/boto/boto3/issues/28

    Args:
        zone_string, a single string representing a tld name for Route53 hosted zone.

    Returns:
        string or None: the 'hostedzone' id, suitable for use in other boto3 Route53 queries.

    >>> tld_to_zone_id(zone_string='asdf.com')
    'Z25GVFQNY7IAXZ'

    >>> tld_to_zone_id('asdf.com')
    'Z25GVFQNY7IAXZ'

    >>> tld_to_zone_id(zone_string='hot_latte.vic')
    'Z2KNNZCC7X2LQZ'

    >>> tld_to_zone_id() # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError:

    >>> tld_to_zone_id(zone_string='') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError:

    >>> tld_to_zone_id(zone_string=['', 'foo']) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError:

    '''
    _zone_id = ''

    try:
        try:
            zone_string = zone_string.strip().strip(".")
            if not zone_string or not zone_string.strip():
                raise ValueError(
                    "tld_to_zone_id missing tld name for hosted zone, but got: '{}'".format(zone_string))
        except Exception as err:
            raise ValueError(
                "tld_to_zone_id requires tld as string arg, but got: '{}'".format(zone_string))
        try:
            r53conn = boto3.client('route53')
            for dict_why in r53conn.list_hosted_zones_by_name()['HostedZones']:
                if str(dict_why['Name']) == str(zone_string) + '.':
                    _zone_id = dict_why['Id'].split('/')[-1]
                    break
        except Exception as err:
            raise EnvironmentError('boto3 call: {}'.format(err))

    except Exception as err:
        raise type(err)('tld_to_zone_id(): {}'.format(err))

    return _zone_id

def tld_in_string(tld, name):
    '''
    Checks to see if tld or domain is the suffix for supplied domain name.
    Warning: Operation is case insensitive (handling domain names), and for
    common convenience, strips whitespace and trailing '.' characters.
    Matches must reach the '.' delimiter in the target name, for example:

       True: fqdn.tld ends foo.fqdn.tld
       True: tld ends foo.fqdn.tld
       False: ld in foo.fqdn.tld
       False: dn.tld in foo.fqdn.tld

    Args:

        tld - string, typically 'fqdn.tld' or 'fqdn.tld.'

        name - string, typiclaly 'foo.bar.fqdn.tld' or 'foo.fqdn.tld.'.

    Returns:
        boolean, true if domain matches the end, false if not.

    >>> tld_in_string('fqdn.tld', 'host.fqdn.tld')
    True

    >>> tld_in_string('fqdn.tld', 'CrazyCaps.FQDN.tld')
    True

    >>> tld_in_string('.tld', 'host.fqdn.tld')
    True

    >>> tld_in_string('tld', 'host.fqdn.tld')
    True

    This functionally succeeds, but not sure if we want to allow
    non-fqdn names in the future:
    >>> tld_in_string('d', 'foo.fqdn.tld')
    True

    >>> tld_in_string('fqdn.tld', 'foo.nope.tld')
    False

    >>> tld_in_string('no.way.jose') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    TypeError

    >>> tld_in_string(['foo', 'bar'], 'baz') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    AttributeError

    >>> tld_in_string() # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    TypeError:

    >>> tld_in_string(None, None) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    AttributeError:

    '''
    try:
        clean_tld = tld.strip().strip(".").lower()
        clean_name = name.strip().strip(".").lower()

        return clean_name.endswith(clean_tld)

    except Exception as err:
        raise type(err)("tld_in_string: tld='{0}', string='{1}': {2}".format(tld, name, err))

def domain_walkback(fqdn):
    '''
    "walk back" a given fqdn from right to left,
    returning a list of legal domain names from shortest to longest.

    Args:
      fqdn - string fqdn, with or without trailing dot.

    Returns:
      tuple of names, starting shortest (end) to longest.
      Names will be stripped of trailing/leading '.' dot chars.

    >>> print domain_walkback('baz.bar.foo.tld')
    ('tld', 'foo.tld', 'bar.foo.tld', 'baz.bar.foo.tld')

    >>> print domain_walkback('baz.bar.foo.tld.')
    ('tld', 'foo.tld', 'bar.foo.tld', 'baz.bar.foo.tld')

    Yep, this is legal, we're not discriminating- just handling dot
    notation namespaces:
    >>> print domain_walkback('baz_bar foo.tld.')
    ('tld', 'baz_bar foo.tld')

    >>> print domain_walkback() # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    TypeError

    >>> print domain_walkback(['foo', 'bar']) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    AttributeError

    >>> print domain_walkback(None) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    AttributeError

    '''
    fqdn_list = []

    try:
        clean_fqdn = fqdn.strip().strip(".").lower().split('.')
        count = len(clean_fqdn)

        while count:
            count = count - 1
            fqdn_list.append('.'.join(clean_fqdn[(count):]))
    except Exception as err:
        raise type(err)("domain_walkback(): {}".format(err))

    return tuple(fqdn_list)

def zone_vpc_associations(zone):
    '''
    Given a route53 zone name, returns a list of all associated VPC's.

    Args: zone - str zone name

    Returns: list of strings, associated VPC ID's.
    If none, returns an empty list.  Yet, private domains must be associated
    with a VPC upon creation.
    '''
    vreturn = []
    try:
        zone_id = tld_to_zone_id(zone)
        pzone_client = boto3.client('route53')

        try:
            zresponse = pzone_client.get_hosted_zone(Id=zone_id)['VPCs']
            for vdict in zresponse:
                upsert_list(vreturn, vdict['VPCId'])
        except Exception as err:
            raise ValueError(err)

    except Exception as err:
        raise type(err)("vpc_domains_enabled(): {}".format(err))

    return vreturn


def vpc_domains_enabled(vic_id):
    '''
    Given a VPC id or name, returns boolean value if *both* of the following
    VPC attributes are set:
         EnableDnsHostnames
         EnableDnsSupport
    Args: vic_id string, vpc name or id

    Returns: boolean, True only if both values are set True.

    Bugs: this is really a clumsy link between AWS groups,
    https://github.com/boto/boto3/issues/546
    and then an alternative interface,
    http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.modify_vpc_attribute
    '''
    try:
        vpc_id = validate_vic_id(vic_id)
        vclient = boto3.client('ec2')
        try:
            enable_dns_support = vclient.describe_vpc_attribute(
                Attribute='enableDnsSupport',
                VpcId=vpc_id,
                DryRun=False
            )['EnableDnsSupport']['Value']
        except Exception as err:
            raise ValueError(err)
        # determinism 2 calls instead of complexity, do it again,
        try:
            enable_dns_hostnames = vclient.describe_vpc_attribute(
                Attribute='enableDnsHostnames',
                VpcId=vpc_id,
                DryRun=False
            )['EnableDnsHostnames']['Value']
        except Exception as err:
            raise ValueError(err)

        if enable_dns_hostnames is True and enable_dns_support is True:
            return True
        else:
            return False

    except Exception as err:
        raise type(err)("vpc_domains_enabled(): {}".format(err))


def domain_find_zone_id(fqdn):
    '''
    Find the shortest zone name in AWS which may contain the supplied fqdn.

    Args:
      fqdn_list - str fqdn

    Returns:
      string, for the fqdn parent zone_id
      If the zone does not exist, returns None.

      Note: this is a best-effort utility.
      We start with the shortest part of the fqdn, so this is not a
      comprehensive test.  For example, 'bar.foo.tld' records may exist under
      the 'foo.tld' zone, yet, 'bar.foo.tld' may also be a zone id name.

    >>> print domain_find_zone_id('baz.bar.foo.tld')
    None

    >>> print domain_find_zone_id('bar.foo.vic')
    Z37EMOGNU1IG6D

    >>> print domain_find_zone_id(None) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    AttributeError

    '''
    try:
        for zone_try in domain_walkback(fqdn):
            zone_id = tld_to_zone_id(zone_try)
            if zone_id:
                return zone_id
    except Exception as err:
        raise type(err)("domain_find_zone_id(): {}".format(err))
    # if we make it here,
    return None

def r53_lookup(name='', dns_type=''):
    '''
    Query AWS Route53 name for it's value.  Much like nslookup(1) or dig(1)
    when queried with short options.

    Args:
        name - str, full domain name to look up, with or without trailing '.'.

        dns_type (optional) - DNS record type, string value one of any AWS supported DNS type:
            A | AAAA | CAA | CNAME | MX | NAPTR | NS | PTR | SOA | SPF | SRV | TXT

    Returns:
        List of string values, (usually only one).
        String values are stripped of leading/trailing " and ' characters.
        Returns empty list if name does not exist.

        When multiple names are encountered, (perhaps different DNS types),
        a ValueError is raised.
    '''
    lookup = []
    try:
        try:
            query = list_dns_names(name=name.strip().strip('.'), dns_type=dns_type)
        except ValueError:
            return lookup
        query = query['names']
        if len(query) > 1:
            raise ValueError("Bailing out, more than one name returned for a single name.")
        for value in query[0]['ResourceRecords']:
            if value['Value']:
                lookup.append(value['Value'].strip('"').strip("'"))
            else:
                lookup.append(value['Value'])
    except Exception as err:
        raise type(err)("r53_lookup(): {}".format(err))
    return lookup

def list_dns_names(name='', zone='', dns_type='', show_zone=False):
    '''
    This function will simply perform the AWS route53 API variant of a DNS lookup.

    This is not fast, nor efficient- but when creating and handling names, there
    is no way to introspect them in Route53 except to ask for them.

    Warning: - boto3 list_resource_record_sets() is lunacy.
    Ancient operator overloader, meets OO, in the age of Web APIquarius.

    Args (name or zone required):

      name - string FQDN for a host, return just the name metadata.
             Wildcard '*' is allowed, (not a regex, a glob).
             Wildcard '*.foo.fqdn.tld' is allowed, leveraging the AWS API
             only on the left-hand side of the domain name.  This is useful
             if you maintain proper DNS namespacing in your naming schemes.

      zone - string for name of DNS zone, with or without trailing '.'
             Returns all names associated with this zone.

    Optional Args:

      dns_type - DNS record type, string value one of any AWS supported DNS type:
            A | AAAA | CAA | CNAME | MX | NAPTR | NS | PTR | SOA | SPF | SRV | TXT

      show_zone - Warning: SLOW. Looking up zone name from zone object id is
                  an absurdly expensive operation.  Yet, for lazy name-based
                  lookups, we may need this from time to time.

    Returns:
      dict of dns name data, focused on the list of 'names' from our request:
      (This list comprises all available DNS types which a single name can have
      a ResourceRecord for in Route53.)

        {'names': [{u'Name': 'baz.foo.tld.',
                    u'ResourceRecords': [{u'Value': '"more"'}],
                    u'TTL': 300,
                    u'Type': 'TXT'}],
         'zone': 'foo.tld.',
         'zone_id': 'Z37EMOGNU1IG6D',
         'zone_meta': {u'CallerReference': 'E982FB15-BEC5-26F2-B7A2-62D159F32C7D',
                       u'Config': {u'Comment': 'test', u'PrivateZone': False},
                       u'Id': '/hostedzone/Z37EMOGNU1IG6D',
                       u'Name': 'foo.tld.',
                       u'ResourceRecordSetCount': 7}}

      If 'name' and 'zone' are both supplied, zone is used to explicitly define
      the "HostedZoneId", so we can get accurate results from our query.
      Considering the following example of legal AWS Route53 dns,

        [zone]   foo.tld.
        [record]       \_ bar.foo.tld
        [zone]   bar.foo.tld
        [record]        \_ baz.bar.foo.tld

      In this example, bar.foo.tld may exist twice.
      When `list_dns_names(name='bar.foo.tld')` is called, we walk back the namespace
      from the tld, returning the 'bar.foo.tld' record.
      `list_dns_names(name='baz.bar.foo.tld')` will fail to return a record, unless
      we define the zone as well,
      `list_dns_names(name='baz.bar.foo.tld', zone='bar.foo.tld')`

      When 'dns_type' is supplied, we filter results to only include records
      of the given type.  This function only allows one record type at a time
      to be queried.

    # Fixtures?

    >>> len(list_dns_names(zone='foo.vic.')['names']) > 1
    True

    >>> len(list_dns_names(zone='foo.vic')['names']) > 1
    True

    >>> len(list_dns_names(name='baz.foo.vic.', dns_type='TXT')) > 1
    True

    >>> len(list_dns_names(name='baz.foo.vic', dns_type='TXT')) > 1
    True

    >>> print list_dns_names(name='baz.foo.vic', dns_type='TXT', show_zone=True)['zone_id']
    Z37EMOGNU1IG6D

    >>> print list_dns_names(name='baz.foo.vic', dns_type='TXT', show_zone='anything')['zone_id']
    Z37EMOGNU1IG6D

    >>> len(list_dns_names(name='baz.foo.vic', dns_type='NOP')) > 1 # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> list_dns_names(name='baz.foo.vic', zone='foo.vic.', dns_type='TXT')['names'][0]['Name']
    'baz.foo.vic.'

    >>> prettyPrint(list_dns_names(name='satellite0.asdf.com')['names'][0]['TTL'])
    300

    >>> print list_dns_names(name='nop.nonexistent.none.') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> print list_dns_names(name=[None]) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    AttributeError

    >>> print list_dns_names(zone=[None]) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> print list_dns_names(name='baz.foo.vic', zone=[None]) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    https://boto3.readthedocs.io/en/develop/reference/services/route53.html#Route53.Client.list_resource_record_sets
    '''
    name_data = {}
    rr_match_set = []

    # TODO: globalize api retry wait and timeout values, defaults with ENV override.
    query_wait = .2
    _max_items = str(100)
    is_truncated = True
    next_marker = None

    if not zone and not name:
        raise ValueError(
            "list_dns_names() requries one of 'name' or 'zone, we got: name='{0}', zone='{1}'".format(
            name, zone))
    try:
        if zone:
            zone_id = tld_to_zone_id(zone)
        else:
            zone_id = domain_find_zone_id(name)

        # This next bit hurts.  AWS API does not appear to guarantee ordering for the list
        # of ResourceRecords (names) returned, yet, does appear to consistently return an
        # ordered list.
        # In order to ensure we pull every possible name match, we must sometimes pull all
        # the names for the zone and filter the result ourselves. srsly fkt, ack.
        # When pulling specific names, there can only currently be 12 types of DNS record
        # type, therefore, assuming an ordered list, (ordered by name), we can pull the
        # named record in batches of 15 (assuming leeway if AWS adds new DNS types),
        # yet still handle pagination if these grow in the future.  Otherwise, we batch
        # 100 at a time, (max), to reduce network API calls.
        try:
           if name:
               start_record = name.strip()
           else:
               start_record = '*'

           if dns_type is not '':
               _max_items = str(100)
           else:
               # maximum list of DNS record tpes is currently 12 types, 2018.03 
               _max_items = str(15)

           while is_truncated:
                r53client = boto3.client('route53')
                if dns_type:
                    response = r53client.list_resource_record_sets(
                        HostedZoneId=zone_id,
                        StartRecordName=start_record,
                        StartRecordType=dns_type,
                        MaxItems=_max_items,
                    )
                else:
                    response = r53client.list_resource_record_sets(
                        HostedZoneId=zone_id,
                        StartRecordName=start_record,
                        MaxItems=_max_items,
                    )
                is_truncated = response['IsTruncated']
                if is_truncated:
                        start_record = response['NextRecordName']

                for name_record in response['ResourceRecordSets']:
                    # match our LH wildcard as well,
                    if name.startswith('*') and name is not '*':
                        name_tail = name.strip().strip('*').strip('.').lower()
                        if name_record['Name'].endswith("{}.".format(name_tail)):
                            upsert_list(rr_match_set, name_record)
                    elif name is not '':
                        if name_record['Name'].startswith(name.strip().lower()):
                            upsert_list(rr_match_set, name_record)
                    else:
                        #print 'else {}'.format(name)
                        upsert_list(rr_match_set, name_record)

        except Exception as err:
            # crude but correct message with botocore error handling hijinks,
            raise ValueError(err)

        # Addition to pop out the SOA and NS records if type is specified,
        if dns_type is not '':
            _tmp_list = []
            for one_name in rr_match_set:
                if one_name['Type'] == dns_type:
                     _tmp_list.append(one_name)
            rr_match_set = _tmp_list
            _tmp_list = ''

        if show_zone:
            zone_info = list_dns_zones()[zone_id]
            name_data['zone_meta'] = zone_info
            name_data['zone'] = zone_info['Name']
        name_data['names'] = rr_match_set
        name_data['zone_id'] = zone_id

    except Exception as err:
        raise type(err)("list_dns_names(): {}".format(err))

    return name_data

def list_dns_zones(zone=None, name=None):
    '''
    Lists DNS Zones or specific zone record, according to Route53.
    http://boto3.readthedocs.io/en/latest/reference/services/route53.html#Route53.Client.list_hosted_zones

    Args:

      None - default behavior returns a list of available zones and associated metadata.
             Critical metadata to include:
             - region (for private hosted zones)
             - VPC id association (for private hosted zones)

      zone - string for name of DNS zone, with or without trailing '.'
             Return format/content is same as 'None' above, but just returns single zone info.

      name - FQDN for a host, return just the parent zone dict.

    Returns:
      dict of zones, keyed by object ID, and associated metadata.

    >>> type_check_first_zone = list_dns_zones().keys()[0].strip()

    >>> len(list_dns_zones('asdf.com').keys()) == 1
    True

    Money,
    >>> len(list_dns_zones(name='satellite0.asdf.com').keys()) == 1
    True

    >>> list_dns_zones(zone='', name='') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    Exception

    >>> list_dns_zones(zone='nonexistent.tld', name='bar') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    Exception

    >>> list_dns_zones(zone='asdf.com', name='nonexistent.asdf.com') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> list_dns_zones(zone='foo.tld', name='bar.foo.tld') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> list_dns_zones(zone='b.tld', name='foo.a.tld') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    Exception

    >>> list_dns_zones(zone='nonexistent.tld', name='foo.nonexistent.tld') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> list_dns_zones(zone='nonexistent.tld', name='nonexistent.tld') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> list_dns_zones(zone=['foo', 'bar'], name='baz.nonexistent.tld') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    Exception

    >>> list_dns_zones(zone='nonexistent.tld', name=['baz', 'bang']) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    Exception

    '''
    zones_return = {}


    # TODO: globalize api retry wait and timeout values, defaults with ENV override.
    query_wait = .2

    _max_items = str(100)
    zone_name = ''

    is_truncated = True
    next_marker = None

    # TODO: seriously boto, you are insane.
    def _id_handler(zoneName):
        '''
        Takes an "evil" boto.list_hosted_zones() 'ID' response,
        and converts it to the sane object ID.

        TODO: decide what we want to do with abysmal boto response,
        e.g. '/hostedzone/Z3FJ1BG2XJIQ7P' not 'Z3FJ1BG2XJIQ7P'
        2 choices:

        1) string slicing , unclear how consistent results can be,
           but less AWS calls for already huge response.

        2) tld_to_usable_lookup() for *every* domain, this makes a ton of
           AWS API calls, but is guaranteed correct. (evil path)


        Args: string, raw ID value, e.g. '/hostedzone/Z3FJ1BG2XJIQ7P'

        Returns: scrubbed ID value, e.g. 'Z3FJ1BG2XJIQ7P'
        '''
        # 1)
        return zoneName.strip('.').strip('/hostedzone')
        # 2)
        #return tld_to_zone_id(zoneName.strip('.'))

    try:
        # bail early if given 'name' is not in our 'zone', because we may have
        # to make numerous AWS API requests later to get the job done:
        if zone is not None and name is not None:
            try:
                if not tld_in_string(is_valid_fqdn(zone), is_valid_fqdn(name)):
                    raise ValueError("'{0}' is not part of the zone '{1}'.".format(
                                                                       name, zone))
            except Exception as err:
                raise Exception("list_dns_zones(): {}".format(err))
        elif zone is None and name is None:
            # This returns the fattest dict, with every possible record.
            try:
                client = boto3.client('route53')
                while is_truncated:
                    try:
                        if next_marker:
                            response = client.list_hosted_zones(
                                Marker = next_marker,
                                MaxItems = _max_items
                            )
                        elif is_truncated:
                            response = client.list_hosted_zones(
                                MaxItems = _max_items
                            )
                    except Exception as err:
                        raise EnvironmentError('boto3 call: {}'.format(err))

                    is_truncated = response['IsTruncated']
                    if is_truncated:
                        next_marker = response['NextMarker']
                    for one_zone in response ['HostedZones']:
                        zones_return[_id_handler(one_zone['Id'])] = one_zone
                    time.sleep(query_wait)
            except Exception as err:
                raise Exception('list_dns_zones(): {}'.format(err))

        elif name is not None:
            # sadly, too many AWS/boto calls required to get a domain 'resource record'.

            # All namespace names which may be part of our zone,
            nameslice = tuple(name.strip().strip(".").split('.')[1:])
            # This loads up a list of possible subdomains to try,
            # starting with *most common* request, (to reduce AWS calls).
            tryzones = []
            upsert_list(tryzones, '.'.join(nameslice[-2:])) # fqdn.tld
            upsert_list(tryzones, '.'.join(nameslice[-1:])) # .tld
            for position in range(len(nameslice))[:-2][::-1]: # remaining *.bar.fqdn.tld
                upsert_list(tryzones, '.'.join(nameslice[position:]))
            tryzones = tuple(tryzones)

            tryzones_filtered = []
            try:
                for maybezone in tryzones:
                    zone_id = tld_to_zone_id(maybezone)
                    if zone_id:
                        upsert_list(tryzones_filtered, zone_id)
                        client = boto3.client('route53')
                        response1 = client.list_resource_record_sets(
                            HostedZoneId = zone_id,
                            StartRecordName = name,
                            MaxItems = _max_items
                            )
                        for resource_record in response1['ResourceRecordSets']:
                            if resource_record['Name'] == name.strip().strip('.') + '.':
                              # SUCCESS, after all that we finally have the record,
                              client = boto3.client('route53')
                              response2 =  client.get_hosted_zone(
                                  Id = zone_id
                              )
                              zones_return[zone_id] = response2['HostedZone']
            except Exception as err:
                raise EnvironmentError('boto3 call: {}'.format(err))

        elif zone is not None:
            # our last chance to do something meaningful,
            # another paginated response,
            zone_id = tld_to_zone_id(zone)
            try:
                client = boto3.client('route53')
                response =  client.get_hosted_zone(
                    Id = zone_id
                )
                zones_return[zone_id] = response['HostedZone']
            except Exception as err:
                raise ValueError, type(err)(
                    "Zone Id '{0}' does not exist: '{1}'".format(zone, err))

        else:
            raise RuntimeError('End of the road: an implementation error has occurred.')

        if not zones_return:
            raise ValueError(
                "Not in route53: zone='{0}', name='{1}'".format(zone, name)) 

    except Exception as err:
        raise type(err)('list_dns_zones(): {}'.format(err))

    return zones_return

def list_iam_roles(vic_id=None, show_policy=False):
    '''
    Checks account for vic-specific IAM roles.

    Args:
        vic_id str, name or vpc id for a vic.
        show_policy bool, also shows associated policies.

    Returns:
        Dict of iam roles, keyed by role id.

    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_roles
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.list_role_policies

    Bugs:
    AWS/boto3 Cannot show tags.
    Boto3 apparently has not implemented any manner by which to fetch
    tags for IAM roles, (even though docs say it's possible,
    https://github.com/boto/boto3/issues/1794).  Therefore, IAM
    role names for VIC-specific resources must be prepended
    with the vic name, e.g. "decaf_sidamo.vic_role_name" to enable
    minimal IAM role management from VIC tooling, (e.g. oldschool
    'PathPrefix' filtering for list_roles().
    '''
    roles_pre_return = {}
    roles_return = {}
    try:

        _page_next = True
        _next_marker = ''
        while _page_next:
            try:
                if _next_marker:
                    iam_client = boto3.client('iam')
                    iam_response = iam_client.list_roles(
                        Marker=_next_marker,
                        MaxItems=100,
                    )
                else:
                    iam_client = boto3.client('iam')
                    iam_response = iam_client.list_roles(
                        MaxItems=100,
                    )
            except Exception as err:
                raise ValueError(err)
            if 'NextMarker' in iam_response:
                _next_marker = response['NextMarker']
            else:
                _page_next = False
                _next_marker = ''
            #prettyPrint(iam_response)

            if 'Roles' in iam_response:
                for eachrole in iam_response['Roles']:
                    roles_pre_return[eachrole['RoleId']] = eachrole

                    # tag method(s) not implemented.
                    # https://github.com/boto/boto3/issues/1794
                    ## iam_tag_response = {}
                    ## try:
                    ##     iam_tag_client = boto3.client('iam')
                    ##     iam_tag_response = iam_tag_client.list_role_tags(
                    ##         RoleName=eachrole['RoleName'],
                    ##         #Marker='string',
                    ##         MaxItems=123,
                    ##     )
                    ## except Exception as err:
                    ##     raise ValueError(err)
                    ## if 'Tags' in iam_tag_response.keys():
                    ##     roles_pre_return[eachrole['RoleId']]['Tags'] = iam_tag_response['Tags']


            if not vic_id:
                roles_return = roles_pre_return
            else:
                for role_id, role_meta in roles_pre_return.iteritems():
                    if role_meta.get('RoleName').startswith(vic_id):
                        roles_return[role_id] = role_meta

            if show_policy:
                for role_id, role_meta in roles_return.iteritems():
                    p_PolicyNames = []
                    pIsTruncated = True
                    pMarker = ''
                    while pIsTruncated:
                        try:
                            if not pMarker:
                                policy_client = boto3.client('iam')
                                policy_response = policy_client.list_role_policies(
                                    RoleName= role_meta.get('RoleName'),
                                )
                            else:
                                policy_client = boto3.client('iam')
                                policy_response = policy_client.list_role_policies(
                                    RoleName= role_meta.get('RoleName'),
                                    Marker=pMarker,
                                )
                        except Exception as err:
                            raise ValueError(err)
                        pIsTruncated = policy_response.get('IsTruncated')
                        pMarker = policy_response.get('Marker')
                        for each_policy in policy_response.get('PolicyNames'):
                            upsert_list(p_PolicyNames, each_policy)
                    roles_return[role_id]['PolicyNames'] = p_PolicyNames

        return roles_return
    except Exception as err:
        raise type(err)('list_iam_roles(): {}'.format(err))


def check_reservation_eip(printlist=None):
    '''
    Checks account reservation of inet elastic IP's.
    (Implicitly uses account for authenticated user).

    Args:
       None - returns reservation int, used int

       printlist - boolean to supply additional list of EIPs and metadata

    Returns: dict with the following information:
        { reservation_count = int(total_eip_reservation)
          reservation_used = int(total_eip_used)
        }
    or, with 'printlist' boolean set,
        { 'reservation_count' = int(total_eip_reservation)
          'reservation_used' = int(total_eip_used)
          eip_reserved={ 'eip_object_id' =
              ( 'eip_ip_addr', boolean_eip_inuse)
        }
    '''
    print 'TODO: check_reservation_eip'

def check_reservations_instances():
    '''
    Checks instances reservations, focused on returning  reservation limit,
    and reservation used.

    Args: none.

    Returns: dict of various instance reservation details,
             focused on reservation int and used count.
    '''
    print 'TODO: check_reservation_hosts'

def fetch_account_id():
    '''
    Reliably fetch and return account ID, and any optional aliases.
    (Implicitly uses account for authenticated user).

    Args: None.

    Returns: Tuple containing account id, followed by list of possible aliases.

    Common usage:
        fetch_account_id()[0] # returns only the account ID string

    There can only be one account ID,
    >>> fetch_account_id()[0]
    '995151524616'

    >>> account_id_data = fetch_account_id()
    >>> print "https://{0}.signin.aws.amazon.com/console".format(account_id_data[0])
    https://995151524616.signin.aws.amazon.com/console

    There may be several account aliases,
    >>> fetch_account_id()[1]
    ['vics']

    >>> for alias in fetch_account_id()[1]: print "https://{0}.signin.aws.amazon.com/console".format(alias)
    https://vics.signin.aws.amazon.com/console

    >>> fetch_account_id(['baz', 'bang']) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    TypeError

    >>> fetch_account_id(None) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    TypeError
    '''

    try:
        try:
            # aws has no spec for this value, but appears to be [0-9],
            try:
                _id = boto3.client('sts').get_caller_identity()['Account']
            except Exception as err:
                raise EnvironmentError('boto3 call: {}'.format(err))

            # aws allows unlimited(?) account aliases
            _aliases = []
            acct_iam = boto3.client('iam').get_paginator('list_account_aliases')
            for page in acct_iam.paginate():
                for _alias in page['AccountAliases']:
                    _aliases.append(_alias)
        except (RuntimeError, TypeError, ValueError, NameError) as err:
                raise type(err)("Invalid arg: {}".format(err))
    except Exception as err:
        raise type(err)('fetch_account_id(): {}'.format(err))

    return (_id, _aliases)

def set_region(region=''):
    '''
    Manual shifter to set a region context for vic library interactions.
    Sets ENV var 'AWS_DEFAULT_REGION' for the runtime process context.

    Checks desired region input against regions that your account actually
    has access to use.

    Args:
       region - optional string value for 'AWS_DEFAULT_REGION'. Strips 
                leading/trailing whitespace on input.

       None (any null value) - useful when calling this function for
            a second time in a program, 

    Returns:
      Sets ENV vars, returns nothing directly.
        - Sets ENV var 'AWS_DEFAULT_REGION' to region specified.
        - Sets ENV var 'AWS_DEFAULT_REGION_RUNTIME_ORIGINAL' to original ENV value,
          unless ENV var already exists, (assumes prior run).
      Else, an error will be raised.  Can be called without consideration for return.

    Use example:
       >> print os.environ['AWS_DEFAULT_REGION']
       us-west-1

       >> set_region(sa-east-1)
       >> print os.environ['AWS_DEFAULT_REGION'], \
       >>     os.environ['AWS_DEFAULT_REGION_RUNTIME_ORIGINAL']
       sa-east-1 us-west-1

       # go do some boto3 action in sa-east-1

       # now we reset back to our original runtime region,
       >> set_region()
       >> print os.environ['AWS_DEFAULT_REGION']
       us-west-1

    >>> set_region()
    >>> print os.environ['AWS_DEFAULT_REGION_RUNTIME_ORIGINAL']
    us-west-1

    # tests core functionality, doctest prints the function return,
    >>> set_region('sa-east-1')
    >>> print os.environ['AWS_DEFAULT_REGION']
    sa-east-1

    # tests that we return nothing, (while we reset for other tests)
    >>> set_region('us-west-1')

    >>> set_region('foo') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> set_region(['first', 2]) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    AttributeError

    '''
    valid_region = False
    try:

        try:
            # dud assignment, tests existence and value
            _dud = os.environ['AWS_DEFAULT_REGION_RUNTIME_ORIGINAL']
        except:
            os.environ['AWS_DEFAULT_REGION_RUNTIME_ORIGINAL'] = os.environ['AWS_DEFAULT_REGION']

        if not region:
            if os.environ['AWS_DEFAULT_REGION_RUNTIME_ORIGINAL']:
                region = os.environ['AWS_DEFAULT_REGION_RUNTIME_ORIGINAL']
            elif os.environ['AWS_DEFAULT_REGION']:
                region = os.environ['AWS_DEFAULT_REGION']

        if os.environ['AWS_DEFAULT_REGION']:
           foo = 'Foo'

        region = region.strip()
        for single_valid in fetch_available_regions():
            if single_valid == region:
                valid_region = region
                os.environ['AWS_DEFAULT_REGION'] = valid_region

    except Exception as err:
        raise type(err)('set_region() error: {}'.format(err))

    if not valid_region:
        raise ValueError("set_region(): supplied region '{0}' does not appear to be a region available to your account.".format(
          region))

def fetch_available_regions():
    '''
    Return a list of regions available to our account.
    similar to, `aws ec2 describe-regions`

    Args: None

    Returns: Dict keyed by RegionName, containing general metadata, including but not limited to:
             "Endpoint": "ec2.ap-south-1.amazonaws.com",

    >>> fetch_available_regions()['us-west-1']['Endpoint']
    'ec2.us-west-1.amazonaws.com'

    >>> fetch_available_regions(['baz', 'bang']) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    TypeError

    >>> fetch_available_regions(None) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    TypeError

    '''
    _avail_regions = {}
    try:
        region_ec2 = boto3.client('ec2')
        response = region_ec2.describe_regions()
        #print  response['Regions']
        for _endpoint in response['Regions']:
            _avail_regions[str(_endpoint['RegionName'])] = {'Endpoint': _endpoint['Endpoint']}
    except Exception as err:
        raise type(err)(
            'Boto, Auth, or Network failure: {}'.format(err))

    return _avail_regions

def region_resolver(startwith=[], allregions=True, geofilter='', geopriority=''):
    '''
    This function returns a list of AWS regions for use in iterative operations.

    This performs a nuanced yet critical job for any cross-region AWS need.
    This function returns an ordered list of AWS regions, for use in any iteration
    across regions for various resources.
    Simply iterating through available regions (fetch_available_regions) can be
    dangerously, nondeterministically, slow.

    The order of names returned is key to allowing programs to efficiently short-circuit
    various operations, (finding a named VIC subnet, for example), yet this function
    can be used to reliably deliver full lists of regions for comprehensive iteration,
    allowing for efficient ordering to reach regions.

    Args:

      allregions - boolean to return all regions, or targeted list.
      startwith - a list of strings, each string of an AWS region, e.g.
                  ['us-west-1'] or ['us-east-2', 'eu-west-1'].  This list
                  may include regions not availale natively to the AWS
                  account we are using, (e.g. govcloud et. al.)
      geofilter, geopriority -
                  both arguments are a  string value which starts the
                  geographic region where the AWS region, e.g. 'us' in
                  us-west-1 or, 'eu' in eu-west-3.

    Usage:

      When called without 'startwith' argument:
        - returned ensures that ENV 'AWS_DEFAULT_REGION' (if set),
          is always the first listed region.
        - when allregion boolean is set, all remaining regions
          available to our account are returned.

      When called with 'startwith' list arguement:
        - returned ensures that listed regions are returned first, maintaining
          the positional order as they were passed in.
        - returned ensures that is followed by ENV 'AWS_DEFAULT_REGION' (if set).
        - when allregion boolean is set, all remaining regions
          available to our account are returned.

      'allregion' additions:
          - only when allregion boolean is set, if the env var
            'AWS_DEFAULT_REGION_RUNTIME_ORIGINAL' has
            been set by 'set_region()', this region will be listed
            between 'AWS_DEFAULT_REGION' and the remaining regions.
          - if geopriority is set, regions starting with this string
            will be listed ahead of others.

          - 'geofilter' is applied to reduce list output after the
             list order has been set, only regions which start with
            the geographic filter will be listed.

          - 'geopriority' will prioritize the single geographic zone
            specified ahead of the remaining valid zones.

    Returns: list of AWS region names, positionally ordered as described above.
    Incorrect or nonexistent region name strings will simply be returned, yet,
    incorrect types or other issues will raise the appropriate errors.


    # disabled doctest tests because AWS API return is nondeterministic in return order.

    >> region_resolver()

    >> region_resolver(geopriority='eu')
    ['us-east-1', 'us-west-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'ap-northeast-2', 'ap-northeast-1', 'sa-east-1', 'ap-southeast-1', 'ca-central-1', 'ap-southeast-2', 'us-west-2', 'us-east-2', 'ap-south-1']

    # noteworthy, region seting test before now sets ENV vars affecting this,
    >> region_resolver(allregions=False)
    ['us-east-1', 'us-west-1']

    >> region_resolver(startwith=['us-foo-1', 'sa-east-1'], allregions=True)
    ['us-foo-1', 'sa-east-1', 'us-east-1', 'us-west-1', 'ap-northeast-2', 'ap-northeast-1', 'ap-southeast-1', 'ca-central-1', 'ap-southeast-2', 'us-west-2', 'us-east-2', 'ap-south-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3']

    >> region_resolver(startwith=['sa-east-1'])
    ['sa-east-1', 'us-east-1', 'us-west-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'ap-northeast-2', 'ap-northeast-1', 'ap-southeast-1', 'ca-central-1', 'ap-southeast-2', 'us-west-2', 'us-east-2', 'ap-south-1']

    >> region_resolver(startwith=['eu-west-3'], geofilter='eu')
    ['eu-west-3', 'eu-central-1', 'eu-west-1', 'eu-west-2']

    >> region_resolver(startwith='eu-west-3') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    AssertionError

    >> region_resolver(startwith=['eu-west-3'], geofilter={'foo': 'Foo'})  # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    TypeError

    '''
    resolved = []
    try:
        if startwith:
            assert not isinstance(startwith, basestring)
            for region_named in startwith:
                upsert_list(resolved, region_named)

        if allregions or not startwith:
            try:
                aws_default_region = os.environ['AWS_DEFAULT_REGION']
                upsert_list(resolved, aws_default_region)
            except:
                pass

            try:
                runtime_original = os.environ['AWS_DEFAULT_REGION_RUNTIME_ORIGINAL']
                upsert_list(resolved, runtime_original)
            except:
                pass

        if allregions:
            available_regions = fetch_available_regions()
            if geopriority:
                for region_valid in available_regions:
                    if region_valid.startswith(geopriority):
                        upsert_list(resolved, region_valid)
            for region_valid in available_regions:
                upsert_list(resolved, region_valid)

        if geofilter:
            _newresolved = []
            for region in resolved:
                if region.startswith(geofilter):
                    upsert_list(_newresolved, region)
            resolved = _newresolved

        # scrub out empty values,
        for regionstring in resolved:
            if not regionstring:
                resolved.remove(regionstring)

        return resolved
    except Exception as err:
        raise type(err)('region_resolver(): {}'.format(err))

def fetch_available_azs(region=None):
    '''
    Return a list of availability zones for a given region, available to our account.
    similar to as `aws ec2 describe-availability-zones --region <region>`

    Args:
        region - optional str, expecting one aws region name.
                 If not supplied, return all known regions and respective AZ's.
                 Warning: requesting all AZ's is a fat request from every region,
                 and therefore wildly nondeterministic time to return.

    Returns: Nested dict keyed by AZ Name, containing general metadata, including
             but not limited to the following example:

        {'us-west-1': {'us-west-1b': {u'Messages': [],
                                      u'RegionName': 'us-west-1',
                                      u'State': 'available'},
                       'us-west-1c': {u'Messages': [],
                                      u'RegionName': 'us-west-1',
                                      u'State': 'available'}}}

    http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.describe_availability_zones
    '''
    azs = {}
    try:

        if not region:
            for region in fetch_available_regions():
                azs[region] = fetch_available_azs(region)[region]

            return azs

        region = region.strip()

        try:
            # if we don't ask using the region endpoint, you *may* get empty results.
            # if we don't filter *by* the region endpoint, you may get other regions az's.
            client = boto3.client('ec2', region_name=region)
            response = client.describe_availability_zones(
                Filters=[
                    {
                        'Name': 'region-name',
                        'Values': [
                            str(region),
                        ]
                    },
                ],
                DryRun=False
            )
        except Exception as err:
            raise ValueError(err)

        azkeyed = {}
        for azone in response['AvailabilityZones']:
            azkeyed[azone.pop('ZoneName')] = azone
        azs[region] = azkeyed

    except Exception as err:
        raise type(err)('fetch_available_azs() error: {}'.format(err))

    return azs

def fetch_live_ipv4_netblocks(vpc=None):
    '''
    Fetch live/used ipv4 netblocks, in one of two ways:

    Args:
        None, queries for a list of used VPC netblocks.
        vpc, optional string of VPC name or object id, queries for all subnet blocks used in the vpc.

    Returns: Dict keyed by VPC *neblock string*, containing VPC metadata.
             If filtering by VPC, same keyed dict contains dict of subnets, keyed by Subnet *netblock string*.
    '''
    print vpc
    print 'TODO: fetch_live_ipv4_netblocks()'

# TODO future stub.
#def fetch_live_ipv6_netblocks(vpc=None):
#    '''
#    The same as fetch_live_ipv4_netblocks(), except specifically for ipv6 blocks.
#    2018 - currently not sane to implement until we have an IPv6 strategy in place.
#    (Possibly acquiring netblocks from IANA here).
#    '''
#    print vpc
#    print 'TODO: fetch_live_ipv6_netblocks()'

def list_lambdas(vic_id=None, region='Undefined'):
    '''
    Queries for information about lambdas.

    Args:
        None - returns all lambda functions for the account.

        vic_id - (str) Optional VIC name or VPC ID to filter query.

        region - (str) Optional AWS region to contstrain results.

    Bugs:
    boto3 lambda list_functions() method consistently returns zero results
    when passed the args MasterRegion and compainion FunctionVersion.
    Noteworthy: boto3 docs for various region specific details appear to be
    misleading, api calls are indeed constrained to a single region.
    '''
    regions = []
    lambdas_pre_return = {}
    lambdas_return = {}
    try:

        if vic_id:
            #if region != 'Undefined':
            #    region = name_to_region(vic_id)
            #upsert_list(regions, region)
            baz = 'baz'
        if region is not 'Undefined':
            regions = upsert_list(regions, region)
        else:
            regions = region_resolver(allregions=True)

        # need to loop, region_name=oneregion
        for oneregion in regions:
            #print oneregion
            _page_next = True
            _next_marker = ''
            while _page_next:
                try:
                    if _next_marker:
                        lam_client = boto3.client('lambda', region_name=oneregion)
                        lam_response = lam_client.list_functions(
                            Marker=_next_marker,
                            MaxItems=50,
                        )
                    else:
                        lam_client = boto3.client('lambda', region_name=oneregion)
                        lam_response = lam_client.list_functions(
                            MaxItems=50,
                        )
                    if 'NextMarker' in lam_response:
                        _next_marker = response['NextMarker']
                    else:
                        _page_next = False
                        _next_marker = ''
                except Exception as err:
                    raise ValueError(err)

                for found_function in lam_response['Functions']:
                    lambdas_pre_return[found_function['FunctionArn']] = found_function
                    lambdas_pre_return[found_function['FunctionArn']]['region'] = oneregion
                    try:
                        l_tag_client = boto3.client('lambda', region_name=oneregion)
                        raw_tag_response = l_tag_client.list_tags(
                            Resource=found_function['FunctionArn']
                        )
                    except Exception as err:
                        raise ValueError(err)
                    if 'Tags' in raw_tag_response: 
                        lambdas_pre_return[found_function['FunctionArn']]['Tags'] = raw_tag_response['Tags']
                        # for consistency in use,
                        lambdas_pre_return[found_function['FunctionArn']]['TagSane'] = raw_tag_response['Tags']
                    else:
                        lambdas_pre_return[found_function['FunctionArn']]['Tags'] = {}
                        lambdas_pre_return[found_function['FunctionArn']]['TagSane'] = {}
                    if 'vic_id' in lambdas_pre_return[found_function['FunctionArn']]['TagSane']:
                        lambdas_pre_return[found_function['FunctionArn']]['vic_id'] = \
                            lambdas_pre_return[found_function['FunctionArn']]['TagSane']['vic_id']
                    else:
                        lambdas_pre_return[found_function['FunctionArn']]['vic_id'] = 'Undefined'

                if vic_id:
                    if lambdas_pre_return[found_function['FunctionArn']]['vic_id'] != 'Undefined':
                        if lambdas_pre_return[found_function['FunctionArn']]['vic_id'] == vic_id:
                            lambdas_return[found_function['FunctionArn']] = \
                                lambdas_pre_return[found_function['FunctionArn']]
                else:
                    lambdas_return[found_function['FunctionArn']] = \
                        lambdas_pre_return[found_function['FunctionArn']]

        return lambdas_return

    except Exception as err:
        raise type(err)('list_lambdas(): {}'.format(err))



def list_sqs_queues(vic_id=None, sqs_id=None, region='Undefined'):
    '''
    Queries for information about SQS queues and endpoints.

    Args:
        None - returns all SQS queues for the account.

        vic_id - (str) Optional VIC name or VPC ID to filter query,
                 returns only SQS queues belonging to a given VPC.
                 Relies on special SQS property of prefix name
                 being the vic_id, yet because SQS names cannot
                 include punctuation, dots are replaced by underscores.

        sqs_id - (str) Optional SQS id to filter query,
                 returns only one SQS queue and metadata.

        region - (str) Optional AWS region to contstrain results.

    Returns:
        A dict keyed by SQS queue ID, for every return type.
        When no args, returns all SQS queues and metadata for the account.
        With vic_id specified, returns all SQS queues attached to, or belonging
        to, a given VPC.
        When sqs_id is specified, returns the same format dict, with only the
        one sqs queue requested.
        When both vic_id and sqs_id are specified, the sqs_id wins, as it is
        the smallest hierarchical unit.

        Important metadata in the SQS endpoint:
         - any associated VPC endpoint relationship where applicable.
           (boto may not do this, raw API call may be necessary)
         - any associated Security Group
    '''
    regions = []
    queues_return = {}
    dead_letter_map = {}
    q_name_prefix = None
    try:
        if sqs_id:
            q_name_prefix = sqs_id
            regions = region_resolver(allregions=True)
        elif vic_id:
            q_name_prefix = vic_id.replace('.', '-')
            upsert_list(regions, name_to_region(vic_id))
        else:
            regions = region_resolver(allregions=True)
        if region is not 'Undefined':
            regions = [region]

        for oneregion in regions:
            # will map as {'parent_path': child_path',} associative array
            region_map_dead_letter = {}

            # fetch all to resolve dead_letter children when singleton return
            # (we are intentionally asking AWS twice here)
            try:
                full_sqs_client = boto3.client('sqs', region_name=oneregion)
                full_sqs_response = full_sqs_client.list_queues()
            except Exception as err:
                raise ValueError(err)

            # There is no paginator (can_paginate() and get_paginator() do not support list_queues)
            if len(full_sqs_response.keys()) >= 1000:
                _lenwarn = "WARNING: SQS API 'list_queues()' 1000 max count reached, there may be more queues than are represented in our response: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs.html#SQS.Client.list_queues"
                print >> sys.stderr, _lenwarn


            if 'QueueUrls' in full_sqs_response.keys():
                for full_q_path in full_sqs_response['QueueUrls']:
                    try:
                        full_dead_client = boto3.client('sqs', region_name=oneregion)
                        full_dead_response = full_dead_client.list_dead_letter_source_queues(
                            QueueUrl=full_q_path
                        )
                    except Exception as err:
                        raise ValueError(err)
                    if 'queueUrls' in full_dead_response.keys():
                        for full_q_linked in full_dead_response['queueUrls']:
                            region_map_dead_letter[full_q_linked] = full_q_path

            if q_name_prefix:
                sqs_response = {} # do not fail for region-specific empty responses
                try:
                    sqs_client = boto3.client('sqs', region_name=oneregion)
                    sqs_response = sqs_client.list_queues(
                        QueueNamePrefix=q_name_prefix
                    )
                except Exception as err:
                    # this is sub-optimal, we want to raise errors for
                    # everything *except* empty results in the request,
                    # (a common case), yet boto3 error handling makes this
                    # extremely difficult.  So, instead, we'll simply return
                    # empty results and move on.
                    sqs_response = {}
            else:
                sqs_response = full_sqs_response

            if 'QueueUrls' in sqs_response.keys():

                for queue in sqs_response['QueueUrls']:
                    raw_tags = {} # totally different than any other AWS object
                    sqs_tag_response = None
                    dead_response = None
                    dead_queue_linked = []
                    q_attributes = {}
                    try:
                        sqs_tag_client = boto3.client('sqs', region_name=oneregion)
                        sqs_tag_response = sqs_tag_client.list_queue_tags(
                            QueueUrl=queue
                        )
                    except Exception as err:
                        raise ValueError(err)

                    if 'Tags' in sqs_tag_response.keys():
                        raw_tags = sqs_tag_response['Tags']

                    try:
                        q_attr_response = None
                        q_attr_client = boto3.client('sqs', region_name=oneregion)
                        q_attr_response = q_attr_client.get_queue_attributes(
                            QueueUrl=queue,
                            AttributeNames=['All',]
                        )
                    except Exception as err:
                        raise ValueError(err)

                    if 'Attributes' in q_attr_response.keys():
                        q_attributes = q_attr_response['Attributes']

                    queue_name = os.path.basename(queue)
                    queues_return[queue_name] = {}
                    queues_return[queue_name]['path'] = queue
                    queues_return[queue_name]['region'] = str(oneregion)
                    queues_return[queue_name]['Tags'] = raw_tags
                    queues_return[queue_name]['TagSane'] = raw_tags # for vic lib consistency
                    if 'vic_id' in raw_tags.keys():
                        queues_return[queue_name]['vic_id'] = raw_tags['vic_id']
                    else:
                        queues_return[queue_name]['vic_id'] = 'undefined tag'
                    queues_return[queue_name]['attributes'] = q_attributes

                    for q_parent, q_child in region_map_dead_letter.iteritems():
                        if q_parent == queue:
                            queues_return[queue_name]['dead_letter_children'] = q_child
                        else:
                            queues_return[queue_name]['dead_letter_children'] = ''
                        if q_child == queue:
                            upsert_list(dead_queue_linked,  q_parent)
                    queues_return[queue_name]['dead_letter_parents'] = dead_queue_linked

        return queues_return

    except Exception as err:
        raise type(err)('list_sqs_queues(): {}'.format(err))

def list_vics_s3_buckets(vic_id=None, bucket_id=None):
    '''
    Queries for information about VIC-created S3 buckets and endpoints.

    Args:
        None - returns all S3 buckets for the account, including VPC
               endpoint data.

        vic_id - (str) Optional VIC name or VPC ID to filter query,
                 returns only S3 buckets with belonging to a given VPC.
                 Also, returns any VPC endpoint metadata relating the VPC
                 and S3 bucket.

        bucket_id - (str) Optional BUCKET id to filter query.
                 returns only one bucket and metadata.

    Returns:
        A dict keyed by bucket ID, for every return type.
        When no args, returns all vic-related buckets for the account.
        This function always returns only the buckets tagged with
        'vic_create_session_id', indicating they belong to a VIC.
        With vic_id specified, returns all buckets attached to or belonging to
        a given VPC.
        With bucket_id speified, returns the same format dict, with only
        the one bucket specified.

        Important Metadata:
          - any VPC endpoint object data where applicable.
          - any associated Security Group

    Bugs:
        The AWS API call to introspect buckets is obnoxously blunt, because
        there are no calls which allow subsets/filtering of the list returned.
        It's all buckets or nothing,
        https://docs.aws.amazon.com/AmazonS3/latest/API/RESTServiceGET.html
        Therefore, this function fetches a "fat" payload of all buckets,
        and strips the result when vic_id or bucket_id are provided.
    '''
    vicbuckets = {}
    try:
        account_id = fetch_account_id()[0]

        try:
            # TODO: pagination?  boto docs are not clear here.
            s3 = boto3.client('s3')
            s3response = s3.list_buckets()
        except Exception as err:
            raise ValueError(err)

        for bucketmeta in s3response['Buckets']:
            target_bucket = {} # clear the target,

            target_bucket[bucketmeta['Name']] = bucketmeta
            target_bucket[bucketmeta['Name']]['Owner'] = s3response['Owner']
            target_bucket[bucketmeta['Name']]['Owner']['account_id'] = account_id
            try:
                region_response = {}
                s3region = boto3.client('s3')
                region_response = s3region.get_bucket_location(
                    Bucket=bucketmeta['Name']
                )
            except Exception as err:
                raise ValueError(err)
            target_bucket[bucketmeta['Name']]['region'] = region_response['LocationConstraint']

            try:
                tag_response = {}
                s3tags = boto3.client('s3')
                tag_response = s3tags.get_bucket_tagging(
                    Bucket=bucketmeta['Name']
                )
            except Exception as err:
                # if we don't even have tags, AWS throws error,
                tag_response = {'TagSet': []}

            target_bucket[bucketmeta['Name']]['Tags'] = aws_tags_dict(tag_response['TagSet'])

            # TODO: workspot: add VPC endpoint metadata here

            if target_bucket.get(bucketmeta['Name']):
                if 'vic_id' in target_bucket[bucketmeta['Name']]['Tags'].keys():
                    target_bucket[bucketmeta['Name']]['vic_id'] = \
                        target_bucket[bucketmeta['Name']]['Tags']['vic_id']
                else:
                    target_bucket[bucketmeta['Name']]['vic_id'] = ''

            if 'vic_create_session_id' in target_bucket[bucketmeta['Name']]['Tags'].keys():
                target_bucket[bucketmeta['Name']]['vic_create_session_id'] = \
                    target_bucket[bucketmeta['Name']]['Tags']['vic_create_session_id']
            else:
                target_bucket[bucketmeta['Name']]['vic_create_session_id'] = ''

            if len(target_bucket[bucketmeta['Name']]['Tags']) == 0 :
                pass
            elif vic_id is not None:
                if vic_id == target_bucket[bucketmeta['Name']]['vic_id']:
                    vicbuckets.update(target_bucket)
            elif bucket_id is not None:
                if bucket_id in target_bucket.keys():
                    return target_bucket # short circuit as soon as we find it
            else:
                vicbuckets.update(target_bucket) 

        return vicbuckets

    except Exception as err:
        raise type(err)('list_vics_s3_buckets() error: {}'.format(err))


def list_rds_instances(vic_id=None, rds_id=None):
   '''
   Queries for information about RDS instances and endpoints.

    Args:
        None - returns all RDS instances for the account, including VPC
               endpoint data.

        vic_id - (str) Optional VIC name or VPC ID to filter query,
                 returns only RDS endpoints with belonging to a given VPC.
                 Also, returns any VPC endpoint metadata relating the VPC.


        rds_id - (str) Optional RDS id to filter query.
                 returns only one bucket and metadata.


    Returns:
        A dict keyed by RDS ID, for every return type.
        When no args, returns all RDS instances/endpoints for the account.
        With vic_id specified, returns all RDS bits attached to or belonging to
        a given VPC.
        With rds_id speified, returns the same format dict, with only
        the one rds specified.

        Important Metadata:
          - any VPC endpoint object data where applicable.
          - any associated Security Group
   '''
   print vic_id
   print rds_id
   print 'TODO: list_rds_instances()'

def list_vpc_endpoints(vic_id=None, region=None):
    '''
    Queries for information about VPC endpoints.

    Similar in spirit to S3, SQS, and other functions here- but focuses on
    returning the vpc endpoints lists.

    Args:
        None - return all VPC endpoints for the account (fat payload).

        vic_id - (str) Optional VIC name or VPC ID to filter query,
                 returns only VPC endpoints associated with the given VPC.

        region - (str) optional aws region to limit query.

    Returns:
        A dict keyed by VPC endpoint object ID, for every return type.
        List size (and aws query) changes based on args presented.

    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_vpc_endpoints
    '''
    endp_response = {}
    _filters = []
    _raw_collection = []
    _next_token = ''

    if vic_id:
        try:
            vpc_id = validate_vic_id(vic_id)
        except:
            return endp_response

    try:
        if region:
            regions = [region]
        else:
            regions = region_resolver()

        if vic_id:
            id_filter = {'Name': 'vpc-id',
                         'Values': [vpc_id,]}
            upsert_list(_filters, id_filter)

        for oneregion in regions:
            set_region(region=oneregion)
            endresponse = False

            while endresponse == False:
                try:
                    if _next_token:
                        endp_client = boto3.client('ec2', region_name=oneregion)
                        endp_resp = endp_client.describe_vpc_endpoints(
                            DryRun=False,
                            Filters=_filters,
                            MaxResults=1000,
                            NextToken=_next_token,
                        )
                    else:
                        endp_client = boto3.client('ec2', region_name=oneregion)
                        endp_resp = endp_client.describe_vpc_endpoints(
                            DryRun=False,
                            Filters=_filters,
                            MaxResults=1000,
                        )
                except Exception as err:
                    raise ValueError(err)

                if 'NextToken' in endp_resp:
                    _next_token = endp_resp['NextToken']
                else:
                    endresponse = True
                for _raw_end in endp_resp['VpcEndpoints']:
                    #if end_type:
                    # needs to be post-request filter, sadly.
                    upsert_list(_raw_collection, _raw_end)

            if _raw_collection:
                for _endp in _raw_collection:
                    endp_response[_endp['VpcEndpointId']] = _endp

                for mkey, mval in fetch_vic_meta(_endp['VpcId'], region=oneregion).iteritems():
                    endp_response[_endp['VpcEndpointId']][mkey] = mval

        return endp_response

    except Exception as err:
        raise type(err)('list_vpc_endpoints() error: {}'.format(err))

def list_available_endpoints(region=None, product=''):
    '''
    Returns a available amazon-owned service endpoints.  Used for deducing
    the service type and name when creating service endpoints in a VIC.

    Args:
        region (str) optional region filter.
        product (str) optional type filter, e.g. 's3', 'sns', etc...

    Returns:
        dict of endpoint types, keyed by region.

    '''
    return_endp = {}
    try:
        if region:
            regions = [region]
        else:
            regions = region_resolver()

        for oneregion in regions:
            return_endp[oneregion] = {}
            endresponse = False
            _next_token = ''
            _response_stack = {}
            _response_stack['ServiceDetails'] = []
            _response_stack['ServiceNames'] = []
            while endresponse == False:
            # Paginate.  Facepalm.
                try:
                    list_endp_client = boto3.client('ec2', region_name=oneregion)
                    if _next_token:
                        list_endp_response = list_endp_client.describe_vpc_endpoint_services(
                            DryRun=False,
                            MaxResults=1000,
                            NextToken=_next_token,
                        )
                    else:
                        list_endp_response = list_endp_client.describe_vpc_endpoint_services(
                            DryRun=False,
                            MaxResults=1000,
                        )
                except Exception as err:
                    raise ValueError(err)
                if 'NextToken' in list_endp_response:
                    _next_token = vpc_response['NextToken']
                else:
                    endresponse = True
                for detail in list_endp_response['ServiceDetails']:
                    upsert_list(_response_stack['ServiceDetails'], detail)
                for named in list_endp_response['ServiceNames']:
                    upsert_list(_response_stack['ServiceNames'], named)

            for named_svc in _response_stack['ServiceNames']:
                named_meta = {}
                for each_meta in _response_stack['ServiceDetails']:
                    if each_meta['ServiceName'] == named_svc:
                        named_meta = each_meta
                named_product = {}
                if product:
                    if named_svc.endswith(product):
                        named_product = named_meta
                else:
                    named_product = named_meta

                if named_product:
                    return_endp[oneregion][named_svc] = named_product

        return return_endp

    except Exception as err:
        raise type(err)('list_available_endpoints() error: {}'.format(err))

def list_sg(vic_id=None, sg_id=None):
    '''
    Queries for information about AWS SG's.

    Args:
        None - return all AWS SG's for the account.

        vic_id - (str) Optional VIC name or VPC ID to filter query,
                 returns only service groups which have been applied to
                 any resource in a given VPC.

        sg_id - (str) Optional Service Group id.
                returns the one given service group and it's metadata,
                AND ADDITIONALLY - returns a sub-list of every AWS resource
                the SG has been applied or related to- from instances,
                to roles, to a myriad of VPC objects.
                (This additional behavior should not exist for the other,
                more top-level list returns, it would simply become too
                huge a response.
         # TODO implementor note: this last one may be difficult to implement.

    Returns:
        A dict keyed by Service Group object id, for all cases.
        If None, return all SG's and basic metadata- but carefully does not
        recursively attach related objects, else this return would be too huge.
        If vic_id, same return as None, but filtered to reliably return
        SG's associated with objects in the vic_id given.
        If sg_id, returns just the one SG in same dict format, yet every
        single Amazon object related to or attached to the given SG should be
        listed.
    '''
    print vic_id
    print sg_id
    print 'TODO: list_sg()'

def list_acl(vic_id=None, acl_id=None):
    '''
    Queries for information about VPC ACL's.

    Args:
        None - return all VPC ACL's across our account.

    vic_id - (str) Optional VIC name or VPC ID to filter query,
             returns only ACL's which belong to, or are attached to,
             the specified VPC.

    acl_id - (str) Optional, ACL object id.
              AND ADDITIONALLY, returns every single object related or
              directly attached to this ACL object, (subnets, mostly).

    Returns:
        A dict keyed by ACL object id, for all cases.
        If None, return all VPC ACL's and metadata across our account.
        if vic_id, reliably return all VPC ACL's which belong to, or are
        attached to, the specified VPC.
        If acl_id, simply return the single ACL and metadata.
    '''
    print vic_id
    print acl_id
    print 'TODO: list_acl()'

def source(fname=None):
    '''
    Simple parse UNIX file for configuration variables, returning a flat
    dict of key/value pairs, in the same order as the lines read from file.

    Things this does not handle:
    Naturally, ignores comments, ignores all non variable declarations.
    Does not expand values which are themselves variables.
    Does not exec values which are subshells or subcommands.
    Does not capture lines which export ENV variables.

    Args:
        fname: string path to file.

    Returns:
        OrdredDict format dict of keys/values
        Mostly strings, yet converts empty Null value to Python None.

    # TODO: this fixture takes some work to get right in doctest processs context:
    #>>> lousy_fixture = '/home/ike/repos/vic'
    #>>> source("{}/etc/vic.conf".format(lousy_fixture))['aws_http_socket_timeout']
    #'5'

    Could use some refinenement but solid outcome,
    >>> source('/dev/null')
    OrderedDict()

    Could use some refinement but solid outcome,
    #>>> source('/nonexistent/path/file') # doctest: +IGNORE_EXCEPTION_DETAIL
    #Traceback (most recent call last):
    #UnboundLocalError

    TODO: we could do well for some limits, (read sh source to mimmic),
    #>>> source('/dev/zero') # doctest: +IGNORE_EXCEPTION_DETAIL

    '''
    return_dict = OrderedDict()

    def _polish_corners(str_val):
        '''
        Helper to strip either "'" or '"' from quoted string values.
        Only operates if both beginning and end of string have the same quotes.
        If this condition is not met, reliably return the string as-is.
        '''
        try:
            if str_val.startswith('"') and str_val.endswith('"'):
                return str_val[1:-1]
            elif str_val.startswith("'") and str_val.endswith("'"):
                return str_val[1:-1]
            else:
                return str(str_val)
        except Exception as err:
            raise type(err)(
                "Internal Error for source(): {}".format(err))

    try:
        conf_file = open(fname)
        for line in conf_file.readlines():
            # strip newlines separately (covers quotes edge case),
            line = line.strip().rstrip()
            if re.match('[a-zA-Z]\w*=', line):
            # regex explained:
            #                re.match('[a-zA-Z]\w*=', line)
            #                     ^      ^       ^ ^^
            #                     |      |       | ||
            # beginning of newline|      |       | ||
            #      alphA, first char only|       | ||
            #                    alphAnum, or '_'| ||
            #      (py equavalent to [a-zA-z0-9_]) ||
            #              zero or more of previous||
            #                var assignment delmiter|
            #
            # Value comes after that, even whitespace is a legal Null.
            # Compiled regex machine is cached during runtime for loop.
                _kvpair = line.split('=', 1)
                try:
                    return_dict[_kvpair[0]] = _polish_corners(_kvpair[1])
                except IndexError:
                    return_dict[_kvpair[0]] = None
        conf_file.close()
    except Exception as err:
        raise type(err)(
            'cannot source() file: {}'.format(err))

    return return_dict

def upsert_list(alist, avalue):
    '''
    A riff on builtin list append which behaves like an upsert.
    Efficiently ensures list elements are unique for appends.

    Args:
        alist: A list.
        avalue: An object to upsert into list.

    Returns:
        The new list.

    '''
    try:
        alist.index(avalue)
    except:
        alist.append(avalue)
    return alist

def sort_nets(list_of_addrs, reverse=False):
    '''
    IP address or network, list numeric sort.

    Args:
        list_of_addrs: A list of IPv4 or IPv6 addresses,
                       with or without cidr notation.

        reverse: boolean, reverses sort output.

    Returns:
        Our list of IP addresses or networks, numerically sorted.

        If input list did not supply CIDR notation, return results append it.

        Duplicate entries are pruned.

        CIDR/netmask sorting is returned in order of smallest network
        to largest, (/32 is returned in front of /24, etc...).
        Therefore, identical addresses are returned in the order of which
        network is smaller first, e.g.:

          10.1.127.248/29 before 10.1.127.248/12

        Yet, network addresses are the primary purpose of the sort, so
        smaller networks may end up following the subnets which contain
        them, e.g.:

          10.0.0.0/12 before 10.1.127.248/29
    '''
    submut_map = {}
    mutant_map = {}
    return_ips = []

    try:
        def _hex_inverter(inhex):
            '''
            inverts hex digits in string for fast size-oriented subnet ordering.
            '''
            outhex = []
            revmap = {'0': 'f', 
                      '1': 'e',
                      '2': 'd',
                      '3': 'c',
                      '4': 'b',
                      '5': 'a',
                      '6': '9', 
                      '7': '8',
                      '8': '7',
                      '9': '6',
                      'a': '5',
                      'b': '4',
                      'c': '3', 
                      'd': '2',
                      'e': '1',
                      'f': '0'}
            try:
                for char in inhex:
                    for i, j in revmap.iteritems():
                         if char == i:
                           outhex.append(char.replace(i, j))
                return ''.join(outhex)
            except Exception as err:
                raise type(err)('_hex_inverter(): {}'.format(err))

        for an_addr in list_of_addrs:
            addr = ipcalc.Network(str(an_addr))
            temp_addr = "{0} {1}".format(
                addr.hex(),
                _hex_inverter(ipcalc.Network(addr.netmask()).hex())
            )
            mutant_map[temp_addr] = str(an_addr)
        sortkey = mutant_map.keys()
        sortkey.sort(reverse=reverse)
        for sorted in sortkey:
            return_ips.append(str(ipcalc.Network(mutant_map[sorted])))
    except Exception as err:
        raise type(err)('sort_nets(): {}'.format(err))

    return return_ips

def sort_ips(list_of_ips, reverse=False):
    '''
    Classic IP address list numeric sort.

    Args:
        list_of_ips: A list of IPv4 addresses.
        reverse: boolean, reverses sort output.

    Returns:
        Our list of IPv4 addresses, numerically sorted.
    '''
    try:
        temp_ip_list = map(socket.inet_aton, list_of_ips)
        temp_ip_list.sort(reverse=reverse)
        return map(socket.inet_ntoa, temp_ip_list)
    except Exception as err:
        raise type(err)('sort_ips(): {}'.format(err))

def is_valid_fqdn(fqdn):
    """
    Determine if a string submitted is in fact a valid DNS record name.
    https://tools.ietf.org/html/rfc1035

    Args:
       fqdn (str)

    Returns:
       if OK validation, original str
       if not validate, raises exception.

    Bugs:
       This is absolutely complete enough for most of our uses, yet, it
       does not count name length or more subtle requirements per RFC1035.
       For example, '=.net' is not a legal name, but we return is as such.
       Further subtle cases require far more complex code.

    >>> is_valid_fqdn('fqdn.tld')
    'fqdn.tld'

    This is actually not legal, we may not want to accept in the future,
    >>> is_valid_fqdn('.tld')
    '.tld'

    >>> is_valid_fqdn('nowayjose') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    Exception

    >>> is_valid_fqdn('') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    Exception

    >>> is_valid_fqdn() # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    TypeError

    """
    try:
        if len(fqdn) > 255:
            raise ValueError(
                'is_valid_fqdn() name too long: {}'.format(fqdn))
        if fqdn[-1] == ".":
            raise ValueError(
                'is_valid_fqdn() name not fully qualified: {}'.format(fqdn))
        if "." not in fqdn:
            raise ValueError(
                'is_valid_fqdn() Not qualified!: {}'.format(fqdn))
        if not re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE):
            raise ValueError(
                'is_valid_fqdn() Not qualified!: {}'.format(fqdn))
        else:
          return fqdn
    except Exception as err:
        raise Exception(
            "is_valid_fqdn() Ecxeption: fqdn='{0}', '{1}'".format(fqdn, err))

def list_compare(a, b):
    '''
    Classic list comparison.

    Args:
        a: List A
        b: List B

    Returns:
        List containing two lists.
        The first list returned contains only the items which were not
        contained in the second, and vice-versa for the second list.
    '''
    return [[x for x in a if x not in b], [x for x in b if x not in a]]

def prettyPrint(anything=None):
    """
    Easy pretty print.
    Expensive, useful for debugging.

    Args: anything, a python object.

    Returns, multi-line string.  Does not break on error.
    """
    import pprint
    try:
        if anything is not None:
            return pprint.pprint(anything)
        else:
            return ""
    except Exception as err:
        raise type(err)("prettyPrint(): {}".format(err))

# py variation on the 3 finger claw, to be used with copious try/except
def yell(msg, _fdout=sys.stderr):
    '''Log to file (usually stderr), with progname: <log>'''
    # Note: refrain from using in libraries, this is here for user programs.
    # Instead, raise warnings.
    print >> _fdout, "{0}: {1}".format(sys.argv[0], msg)
    _fdout.flush()

def die(msg, _exit=111, _fdout=sys.stderr):
    '''Exit with a log message (usually a fatal error)'''
    # Note: refrain from using in libraries, this is here for user programs.
    # Instead, raise errors.
    yell(msg, _fdout)
    sys.exit(_exit)

def debug(msg, outfile=sys.stderr):
    '''Print msg (usually stderr), with progname: <msg>'''
    if os.environ.get('DEBUG'):
        print >> outfile, "# {0}: {1}".format(sys.argv[0], msg)
        outfile.flush()

def flatten_dict(dd, separator='_', prefix=''):
    '''
    Flatten a dict object into key/value pairs.
    '''
    return { prefix + separator + k if prefix else k : v
             for kk, vv in dd.items()
             for k, v in flatten_dict(vv, separator, kk).items()
             } if isinstance(dd, dict) else { prefix : dd }

# TODO: consolidate info_vicnets() and info_vicnames()
def info_vicnames():
    '''
    For a given account, returns a list of all 'vicname' names.

    Args: None, implicit dependencies on:
       - AWS account route53 access
       - initalized 'info' zone, e.g. 'info.vic'

    Returns: A dict containing three lists of strings, just the name, no tld:
       - every 'vicname' initalized in account.
       - every used vicname
       - every available vicname
    '''
    all_vicinfo = {}

    def _format_name(instring):
        _clipped = re.sub('^used\.', '', instring.strip().strip('.'))
        return _clipped.split('.', 1)[0]

    try:
        # TODO get configured vic info_domain
        vic_config = vics_loadconfig()
        vic_tld = vic_config['vic_tld']
        info_domain = 'info.{}'.format(vic_tld)

        all_infoTXT_query = list_dns_names(
            zone=info_domain,
            dns_type='TXT',
        )

        all_vic_names = []
        used_vic_names = []
        for namedict in all_infoTXT_query['names']:
            if '.vicname.' in namedict['Name']:
                if namedict['Name'].startswith('used.'):
                    used_vic_names.append(_format_name(namedict['Name']))
                else:
                    all_vic_names.append(_format_name(namedict['Name']))

        free_vic_names = list_compare(all_vic_names, used_vic_names)[0]

        all_vicinfo = {
            'all_names': sorted(all_vic_names),
            'used_names': sorted(used_vic_names, reverse=True),
            'available_names': sorted(free_vic_names),
        }

    except Exception as err:
        raise type(err)('info_vicnames(): {}'.format(err))

    return all_vicinfo

# TODO: consolidate info_vicnets() and info_vicnames()
def info_vicnets():
    '''
    For a given account, returns a list of all 'vicnet' DNS entries.

    Args: None, implicit dependencies on:
       - AWS account route53 access
       - initalized 'info' zone, e.g. 'info.vic'

    Returns: A dict containing three lists of strings which are valid VIC supernets:
       - every 'vicnet' initalized in account
       - every used vicnet
       - every available vicnet
    '''
    all_vicinfo = {}

    def _format_netblock(instring, info_domain):
        _clipnet = re.sub('^used\.', '', instring.strip().strip('.'))
        _clipnet = re.sub(".vicnet.{}$".format(info_domain), '', _clipnet).replace('_', '/', 1)
        return _clipnet

    try:
        # TODO get configured vic info_domain
        vic_config = vics_loadconfig()
        vic_tld = vic_config['vic_tld']
        info_domain = 'info.{}'.format(vic_tld)

        all_infoTXT_query = list_dns_names(
            zone=info_domain,
            dns_type='TXT',
        )

        all_vic_nets = []
        used_vic_nets = []
        for namedict in all_infoTXT_query['names']:
            if '.vicnet.' in namedict['Name']:
                if namedict['Name'].startswith('used.'):
                   used_vic_nets.append(_format_netblock(namedict['Name'], info_domain))
                else:
                    all_vic_nets.append(_format_netblock(namedict['Name'], info_domain))

        free_vic_nets = list_compare(all_vic_nets, used_vic_nets)[0]

        all_vicinfo = {
            'all_nets': sort_nets(all_vic_nets),
            'used_nets': sort_nets(used_vic_nets, reverse=True),
            'available_nets': sort_nets(free_vic_nets),
        }

    except Exception as err:
        raise type(err)('info_vicnets(): {}'.format(err))

    return all_vicinfo


# TODO: generalize these lazy loadconfig functions into a single loader
# which respects PATH, including relative location.
def vics_loadconfig(configpath=None):
    '''
    Convenience function for vic tooling, for loading often used config.

    Args:
       configpath - string path to vic config file.
       Defaults to '<myhier>/etc/vic.conf' if not supplied.

    Returns:
        Sourced config file dict.
    '''
    try:
        if not configpath:
            dothere = os.path.dirname(os.path.normpath(sys.argv[0]))
            myhier = os.path.dirname(dothere)
            configpath = str(myhier + '/etc/vic.conf')

        return source(configpath)

    except Exception as err:
        raise type(err)('vics_loadconfig() error: {}'.format(err))

# TODO: generalize these lazy loadconfig functions into a single loader
# which respects PATH, including relative location.
def vics_loadconfig_net(configpath=None):
    '''
    Convenience function for vic tooling, often used.
    Loads network configuration from supplied file,
    If config path not supplied, we try a default location.

    Args:
       configpath - string path to network config file.
       Defaults to '<myhier>/etc/vic_netbase.conf' if not supplied.

    Returns:
        Sourced config file dict.
    '''
    try:
        if not configpath:
            dothere = os.path.dirname(os.path.normpath(sys.argv[0]))
            myhier = os.path.dirname(dothere)
            configpath = str(myhier + '/etc/vic_netbase.conf')

        return source(configpath)

    except Exception as err:
        raise type(err)('vics_loadconfig_net() error: {}'.format(err))


def vics_supernets_config(configpath=None):
    '''
    Convenience function for vic tooling, often used.
    From network config, return a list of all possible VIC IPv4 supernets.

    Args:
      configpath - string path to config file, where we expect to pick up:

           global_supernet (the base for all possible VICS) 
           vic_supernet (the full size of each actual vic)

    Returns:
       tuple of IPv4 netblock strings in CIDR format.
    '''
    try:
        netconf = vics_loadconfig_net(configpath)

        return ipv4_contiguous(
            supernet=ipcalc.Network(netconf['global_supernet']),
            subnet_cidr=netconf['vic_supernet']
        )

    except Exception as err:
        raise type(err)('vics_supernets() error: {}'.format(err))

def ip_net_cidr(address):
    '''
    Given an IP address in CIDR format, return the network name
    in cidr notation.
    Helper, simply moves IP target to ipcalc network() name.
    IPv4/IPv6 compatible.

    Args:
        address - IP string or ipcalc object.
        Single IP address without cidr will be handled as single address.

    Returns:
        ipcalc network object, with same cidr as what came in.
    '''
    try:
        ipin = ipcalc.Network(address)
        in_addr = ipin.network()
        in_cidr = ipin.subnet()

        return ipcalc.Network("{0}/{1}".format(in_addr, in_cidr))

    except Exception as err:
        raise type(err)('ip_net_cidr() error: {}'.format(err))

def vic_net_config_physical(vic_name=None, vic_net=None, configpath=None, region=None):
    '''
    Intended to be used for:
        - defining physical AWS AZ-aware vic subnets
        - comparing existing vic to existing config template

    Wraps our logical networks and splits them out by for use in multiple AZ's.

    Args:
        region = A valid AWS region id string.
        see vic_net_config_logical()

    Returns:
       Compound ddict describing a vic network structure, suitable for creating VPC/subnets.

    Bugs:
       IPv4 only, (yet logical companion is IP config agnostic).
    '''

    physical = {'vpc_supernet': {}, 'logical_map': {}}
    _subnets = {}

    try:

        # Must supply name and network,
        if not vic_name:
            raise ValueError("'vic_name' string must be supplied to vic_net_config_physical().")
        if not vic_net:
            raise ValueError("'vic_net' string must be supplied to vic_net_config_physical().")

        if region:
            set_region(region)
            # else rely on aws_default_region in ENV from vic.conf
        elif os.environ.get('AWS_DEFAULT_REGION'):
            region = os.environ.get('AWS_DEFAULT_REGION')
        else:
            raise ValueError("vic_net_config_physical(): no supplied 'region' or ENV 'AWS_DEFAULT_REGION'.")

        # construct our logical subnet mapping,
        logical = vic_net_config_logical(vic_name, vic_net, configpath)

        # first, sort out how we need to slice the blocks,
        az_count = int(logical['az_distribution'])
        if az_count == 1:
            net_step = 0
        elif az_count == 2:
            net_step = 1
        elif 3 <= az_count <= 4:
            net_step = 2
        elif 5 <= az_count <= 8:
            net_step = 3
        elif 9 <= az_count <= 16:
            net_step = 4
        elif 17 <= az_count <= 32:
            net_step = 5
        elif 33 <= az_count <= 64:
            net_step = 6
        elif 65 <= az_count <= 128:
            net_step = 7
        else:
            raise ValueError("az_distribution '{}' outside of maximum 128 subents for AWS Availability Zones.".format(
                az_count))

        if region:
            set_region(region)
            # else rely on aws_default_region in ENV from vic.conf
        elif os.environ.get('AWS_DEFAULT_REGION'):
            region = os.environ.get('AWS_DEFAULT_REGION')
        else:
            raise ValueError("vic_net_config_physical(): no supplied 'region' or ENV 'AWS_DEFAULT_REGION'.")

        # find available AZ's in our AWS region,
        az_dict = {}
        az_query = fetch_available_azs(region=region)[region]
        # strip down to AZ's in 'available' state,
        for az in az_query.keys():
            if az_query[az]['State'] == 'available':
                az_dict[az] = az_query[az]
        # ensure we have enough AZ's to cover our 'az_distribution' configured count:
        if len(az_dict.keys()) < az_count:
            raise IndexError("Not enough AZ's available in {0} region to meet 'az_distribution' count {1}: {2}".format(
                region, az_count, az_dict.keys()))

        az_sorted = az_dict.keys()
        az_sorted.sort()

        for logiconf in logical.keys():
            inet_facing = False
            internal_only = False
            if logiconf.startswith('vpc_supernet'):
                physical['vpc_supernet'] = {
                    'name': "{0}.{1}".format(vic_name, logical['vic_tld']).lower(),
                    'netblock': logical['vpc_supernet'],
                }
            elif logiconf.startswith('subnet_'):
                # slice the logical network here,
                shortname = logiconf.strip()[7:].lower()
                logical_name= "{0}.{1}.{2}".format(shortname, vic_name, logical['vic_tld']).lower()
                loginet = logical[logiconf]['network']
                subnet, subcidr = loginet.split('/')
                physical['logical_map'][logical_name] = loginet
                if logiconf in logical['inet_facing_logical_nets']:
                    inet_facing = True
                if logiconf in logical['internal_only_logical_nets']:
                    internal_only = True

                nextnet = subnet

                for subcount in range(az_count):
# TODO: future stub, allow for optional "preferred AZ" config handling here.
                    az = az_sorted[subcount]
                    physical_name = "{0}.{1}".format(az, logical_name)
                    _subnets[physical_name] = {}
                    _subnets[physical_name]['availability_zone'] = az
                    new_cidr = int(subcidr) + int(net_step)
                    nettemp = "{0}/{1}".format(nextnet, new_cidr)
                    _subnets[physical_name]['network'] = nettemp
                    # TODO move in defaults handling to this block

                    # slice out our soft subnet for applied routing uses,
                    target_routing_block = "{0}/{1}".format(
                        ipcalc.Network(nettemp).network(),
                        logical['default_routing_block'].strip().strip('/'))
                    _subnets[physical_name]['routing_block'] = str(target_routing_block)

                    # slice out our soft subnet for applied plubing uses,
                    target_net_plumbing = "{0}/{1}".format(
                        ip_next(target_routing_block).network(),
                        logical['default_net_plumbing'].strip().strip('/'))
                    _subnets[physical_name]['net_plumbing'] = str(target_net_plumbing)

                    target_net_first_dhcp = "{0}".format(
                        ipcalc.Network(ip_next(target_net_plumbing).network()))
                    _subnets[physical_name]['dhcp_first_available'] = str(target_net_first_dhcp)

                    target_net_last_dhcp = "{0}".format(
                        ipcalc.Network(ipcalc.Network(nettemp).host_last()))
                    _subnets[physical_name]['dhcp_last_available'] = str(target_net_last_dhcp)

                    target_routing_gateway = ipcalc.Network(target_routing_block).host_first()
                    _subnets[physical_name]['gateway'] = str(target_routing_gateway)

                    _subnets[physical_name]['logical_association'] = {}
                    _subnets[physical_name]['logical_association']['name'] = logical_name
                    _subnets[physical_name]['logical_association']['network'] = loginet

                    _subnets[physical_name]['inet_facing'] = inet_facing
                    _subnets[physical_name]['internal_only'] = internal_only

                    # pass the ball for the next AZ,
                    nextnet = ip_next(nettemp).network()
            else:
                physical[logiconf] = logical[logiconf]

        physical['vpc_supernet']['subnets'] = _subnets

    except Exception as err:
        raise type(err)('vic_net_config_physical() error: {}'.format(err))

    return physical

def vic_net_config_logical(vic_name=None, vic_net=None, configpath=None):
    '''
    Intended to define logical vic network layout from configuration.

    Given a vic name and vpc supernet, Returns netblock structure for a vic.
    Structure (like subnet count, and their names), is derived from vic config.
    *noteworthy*: this explicitly does not query AWS for state information for
    a running vic.

    The subnet calculations below are critical to pre-empting issues which arise
    from contiguous  subnets allocated which do not actually fall into mathematically
    possible subnet boundaries.  The nastier bits of this function get this sorted
    out for us.

    For an example of such netblocks (and the boundary condition this config prep
    safely takes care of for us in advance of creating any VPC/subnet/objects):

    10.0.0.0/24 - (range 10.0.0.0 - 10.0.0.255)
    Next network starts at 10.0.1.0, and say we want a /23 next:
    10.0.1.0/23 - (range 10.0.0.0 - 10.0.1.255)
    OVERLAP!

    We need to bump our "next network" start address to at minimum the next
    /23 boundary,
    10.0.1.0/23 (range 10.0.2.0 - 10.0.3.255)

    Alternatively, if we had an even bigger next netblock, we need to jump
    forward by the size of the larger netblock:
    10.0.1.0/22 (10.0.0.0 - 10.0.3.255)
    OVERLAP! instead, using the larger network size, we jump ahead to the
    proper block:
    10.0.0.0/22 (start point as soft mask), takes us to:
    10.0.4.0/22 (10.0.4.0 - 10.0.7.255)

    Args:
        vic_name - string vic_name (not fqdn, just the name)
        vpc_supernet - the supernet address for this vic
            (with or without cidr, config will override)
        configpath - path to vic netbase config, (defaults from this script)

    Returns:
       dict describing a vic network structure

    Bugs:
       'default_routing_block' and 'default_net_plumbing' for each subnet
       are not tested for supernet envelope bursting, (yet vpc/subnet relations
       are tested).
       http://blackskyresearch.net/plate_spinning.jpg
    '''
    #vicd = OrderedDict()
    vicd = {}
    lastsuper = None
    lastsub = None
    nextaddr = None
    ok_overlap = True

    try:
        vicd['vic_name'] = vic_name
        # strip cidr from input vic_net,
        vic_net = ip_net_cidr(str(vic_net).split('/')[0])
        # load our network config
        netconf = vics_loadconfig_net(configpath)
        # quick peek in common config,
        vicd['vic_tld'] = vics_loadconfig()['vic_tld']

        try:
            vicd['global_supernet'] = str(ip_net_cidr(netconf.pop('global_supernet').strip()))
        except:
            vicd['global_supernet'] = '0.0.0.0/0'

        try:
            vicd['inet_facing_logical_nets'] = \
                netconf['inet_facing'].strip().split(' ')
            del netconf['inet_facing']
        except:
            vicd['inet_facing_logical_nets'] = []
        if vicd['inet_facing_logical_nets'][0] == '':
            del vicd['inet_facing_logical_nets'][0]

        if len(vicd['inet_facing_logical_nets']) > 1:
            raise ValueError(
                "Only one 'inet_facing' logical network can be defined, multiple configured: {}".format(
                    vicd['inet_facing_logical_nets']
                )
            )
        if len(vicd['inet_facing_logical_nets']) < 1:
            raise ValueError(
                "At least one 'inet_facing' logical network must be defined, none configured: {}".format(
                    vicd['inet_facing_logical_nets']
                )
            )

        try:
            vicd['internal_only_logical_nets'] = \
                netconf['internal_only'].strip().split(' ')
            del netconf['internal_only']
        except:
            vicd['internal_only_logical_nets'] = []


        ######################################################################
        # Calculate our vic supernet, (overriding cidr with configured)
        try:
            # Calculate our vic supernet, (overriding cidr with configured)
            vicd['vic_supernet'] = str(
                    ip_net_cidr(
                    "{0}/{1}".format(
                        str(vic_net).strip().split('/')[0], 
                        netconf.pop('vic_supernet').strip().strip('/')
                    )
                )
            )
            lastsuper = ip_prior(vicd['vic_supernet'])
            # start at our vic superblock base,
            nextaddr = ipcalc.Network(vicd['vic_supernet']).network()
        except KeyError as err:
            raise KeyError("Config value 'vic_supernet' does not seem to exist: {}".format(err))
        except Exception as err:
            raise type(err)("config problem calculating 'vic_supernet': {}".format(err))

        ######################################################################
        # Calculate our reserved half and VPC supernet first,
        # in order of appearance in the config file:
        for conf_expr in netconf.keys():
            if conf_expr.endswith('_supernet'):
                conf_cidr = str(netconf.pop(conf_expr).strip().strip('/'))
                _nextaddr = nextaddr
                conf_super = ip_net_cidr(
                    "{0}/{1}".format(
                        str(nextaddr).strip().split('/')[0],
                        conf_cidr
                    )
                )
                target_super = conf_super
                # check that we're beyond our last network boundary,
                if str(target_super.network()) == str(ip_net_cidr(lastsuper).network()):
                    # first, try jumping one block forward using smaller boundary of the two nets,
                    # to reset boundary,
                    smallcidr = max(
                        int(str(target_super).split('/')[1]),
                        int(ipcalc.Network(lastsuper).subnet())
                    )
                    nextaddr = ip_next(
                        '{0}/{1}'.format(
                            ip_next(lastsuper).network(),
                            smallcidr
                        )
                    )
                    target_super = ip_net_cidr(
                        "{0}/{1}".format(
                            str(nextaddr).strip().split('/')[0],
                            conf_cidr
                         )
                    )
                    # last, try the larger boundary of the two nets to reset boundary,
                    if target_super in ip_next(lastsuper):
                        # reset our target,
                        target_super = conf_super
                        nextaddr = _nextaddr
                        largecidr = min(
                            int(str(target_super).split('/')[1]),
                            int(ipcalc.Network(lastsuper).subnet())
                        )
                        nextaddr = ip_next(
                            '{0}/{1}'.format(
                                ip_next(lastsuper).network(),
                                largecidr
                            )
                        )
                        target_super = ip_net_cidr(
                            "{0}/{1}".format(
                                str(nextaddr).strip().split('/')[0],
                                conf_cidr
                             )
                        )
                # check if we now have past the boundary of our top level supernet,
                if not target_super.network() in ipcalc.Network(vicd['vic_supernet']):
                    raise ValueError("configured block '{}' '{}' is not iside of vic_supernet {}.".format(
                        conf_expr, target_super, ipcalc.Network(vicd['vic_supernet'])))
                vicd[conf_expr] = str(target_super)
                lastsuper = ip_net_cidr(target_super)
                nextaddr = ip_next(target_super)

        ######################################################################
        # All remaining subnet operations happen inside of vpc_supernet,
        lastsub = ip_prior(vicd['vpc_supernet'])
        _nextaddr = ipcalc.Network(vicd['vpc_supernet']).network()
        nextaddr = _nextaddr
        for conf_expr in netconf.keys():
            if conf_expr.startswith('subnet_'):
                conf_cidr = str(netconf.pop(conf_expr).strip().strip('/'))
                # reset our position to the base of vpc_supernet,
                conf_sub = ip_net_cidr(
                    "{0}/{1}".format(
                        str(nextaddr).strip().split('/')[0],
                        conf_cidr
                    )
                )
                target_sub = conf_sub

                # check that we're beyond our last network boundary,
                if str(target_sub.network()) == str(ip_net_cidr(lastsub).network()):
                    smallcidr = max(
                        int(str(target_sub).split('/')[1]),
                        int(ipcalc.Network(lastsub).subnet())
                    )
                    nextaddr = ip_next(
                        '{0}/{1}'.format(
                            ip_next(lastsub).network(),
                            smallcidr
                        )
                    )
                    target_sub = ip_net_cidr(
                        "{0}/{1}".format(
                            str(nextaddr).strip().split('/')[0],
                            conf_cidr
                         )
                    )
                    # last, try the larger boundary of the two nets to reset boundary,
                    if target_sub in ip_net_cidr(ip_next(lastsub)):
                        #reset our target,
                        target_sub = conf_sub
                        #nextaddr = _nextaddr
                        largecidr = min(
                            int(str(target_sub).split('/')[1]),
                            int(ipcalc.Network(lastsub).subnet())
                        )
                        nextaddr = ip_next(
                            '{0}/{1}'.format(
                                ip_next(lastsub).network(),
                                largecidr
                            )
                        )
                        target_sub = ip_net_cidr(
                            "{0}/{1}".format(
                                str(nextaddr).strip().split('/')[0],
                                conf_cidr
                             )
                        )
                # check if we now have past the boundary of our top level supernet,
                if not target_sub.network() in ipcalc.Network(vicd['vpc_supernet']):
                    raise ValueError("Config error, '{}' '{}' is not iside of vpc_supernet {}.".format(
                        conf_expr, target_sub, ipcalc.Network(vicd['vpc_supernet'])))
                elif not target_sub.broadcast() in ipcalc.Network(vicd['vpc_supernet']):
                    raise ValueError("Config error, '{}' '{}' stretches beyond vpc_supernet {}.".format(
                        conf_expr, target_sub, ipcalc.Network(vicd['vpc_supernet'].strip.strip('/'))))

                target_routing_block = "{0}/{1}".format(
                    target_sub.network(),
                    netconf['default_routing_block'].strip().strip('/'))

                # test routing gateway but don't set it.
                target_routing_gateway = ipcalc.Network(target_routing_block).host_first()
                for increment in range(int(netconf['default_routing_gateway']) - 1):
                    target_routing_gateway = ip_next(target_routing_gateway).network()
                if not target_routing_gateway in ipcalc.Network(target_routing_block):
                    raise ValueError("Config 'default_routing_gateway' positon '{0}', beyond 'default_routing_block' '{1}'.".format(
                        netconf['default_routing_gateway'], target_routing_block))

                target_net_plumbing = "{0}/{1}".format(
                    ip_next(target_routing_block).network(),
                    netconf['default_net_plumbing'].strip().strip('/'))

                vicd[conf_expr] = {
                                      'network': str(target_sub),
                                      'routing_block': str(target_routing_block),
                                      'net_plumbing': str(target_net_plumbing),
                                  }

                lastsub = ip_net_cidr(target_sub)
                nextaddr = ip_next(target_sub)

        for remaining in netconf.keys():
            vicd[remaining] = netconf[remaining]

    except Exception as err:
        raise type(err)('vic_net_config_logical() error: {}'.format(err))

    return vicd

def ipv4_contiguous(supernet=None, subnet_cidr=None):
    '''
    Given an ipv4 supernet and subnet size, return list of contiguous ,
    non-overlapping possible subnets.

    Args:
      supernet - string ipv4 netblock in cidr format, or, ipcalc object
      subnet_cidr - string or int ipv4 cidr, with or without leading '/'

    Returns:
       tuple of IPv4 netblock strings in CIDR format.

    Bugs:
       Not handling netblocks which reside in the very beginning or
       the very end of the complete IPv4 address range.  Calling it
       an edge case not worth the work right now, (our current work
       is all well within RFC1918, nowhere near internet edges).

    # TODO: <cough>tests</cough>
    #>>> ipv4_contiguous('10.0.0.0/8', '/10')

    '''
    all_subnets = []
    try:

        global_supernet = ipcalc.Network(supernet)
        subnet_size = str(subnet_cidr).strip().strip('/')

        stop_net = ip_next(global_supernet)
        inside_boundary = True
        next_net = None

        while inside_boundary:
            if next_net:
                target_supernet = ipcalc.Network("{0}/{1}".format(
                    next_net.network(), subnet_size))
            else:
                target_supernet = ipcalc.Network("{0}/{1}".format(
                    global_supernet.network(), subnet_size))
            next_net = ip_next(target_supernet)
            if stop_net in target_supernet:
                inside_boundary = False
            else:
                upsert_list(all_subnets, str(target_supernet))

    except Exception as err:
        raise type(err)('ipv4_contiguous() error: {}'.format(err))

    return tuple(all_subnets)

def ip_next(ip, in_mask=None, out_mask=None, _prev=False):
    '''
    Given an IP address or network, Returns next sequential IP address.
    Useful for calculating contiguous  netblocks.

    Types handled are inherited from the ipcalc module.

    Common usage:
      ip_next('127.0.0.5')
      # returns next IP address object,
      # '127.0.0.5/32'

      ip_next('127.0.0.5', out_mask=29)
      # returns next IP object at /29 boundary,
      # '127.0.0.8/29'

      ip_next('127.0.0.5/24')
      # returns next IP object as /24 block,
      # '127.0.1.0/24'

      ip_next('127.0.0.5/22', in_mask=24)
      # returns next /24 netblock, at /22 boundary,
      # '127.0.4.0/24'

    Args
    Required):

      ip: auto-coerced, IPv4 or IPv6, with or without netmask.
      type can be any of: :class:`IP` or str or long or int

    Optional:

      in_mask: supply input ip mask, only used if a netmask is
      not supplied with the ip object.
      Alternatively, this can more commonly be supplied in the
      ip arg using cidr notation, e.g. '127.0.0.3/29'

      out_mask: return object netmask
      type can be any of: str or int, octal or cidr formats.
      IMPORTANT: if the ip supplied is a single address,
      then out_mask is applied to it, so we don't overlap or start
      cidr blocks in non-contiguous  sections of ip space.

      _prev: boolean to return previous netblock, used to simplify 
      ip_prior() by re-using this function. 

    Returns:
      ipcalc IP address object
      If '*_mask' options are not specified, we return the single IP, (e.g. /32)

      If 'mask' is specified, we return the next network block:
      - if out_mask is only specified, we treat the incoming IP as the same
        size netblock.
      - if in_mask is specified, *or*, if the ip is specified in cidr notation,
        that block used to specify the entire block for the address.

    Bugs:
      A little loosey-goosey with cidr interfaces, provides too much ambiguity
      as to what various inputs will provide, (e.g. cidr string vs. ipcalc object
      which assumes cidr, and ambiguous kwargs relationship on input).

    For more information on using ipcalc,
      http://ipcalc.rtfd.org/
      https://github.com/tehmaze/ipcalc

    >>> ip_next('127.0.0.5')
    Network('127.0.0.6')

    >>> ip_next('127.0.0.5', out_mask=29)
    Network('127.0.0.8/29')

    >>> ip_next('127.0.0.5/24')
    Network('127.0.1.0')

    >>> ip_next('127.0.0.5', in_mask=24)
    Network('127.0.1.0')

    >>> ip_next('127.0.0.5/22', in_mask=24)
    Network('127.0.4.0')

    >>> ip_next('127.0.0.5/29')
    Network('127.0.0.8')

    >>> ip_next('1') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> ip_next(None) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> ip_next(['127.0.0.5', '127.0.0.6']) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    AttributeError

    '''
    try:

        # aligns us on logical subnet boundaries,
        if out_mask:
            if not in_mask:
                in_mask = out_mask

        if not _prev:
            inip = str(ipcalc.Network(ip, mask=in_mask).broadcast())
            incr = 1
        else:
            inip = str(ipcalc.Network(ip, mask=in_mask).network())
            incr = -1

        next_pos = str(ipcalc.Network(
            (ipcalc.Network(inip).network_long() + incr),
             mask=out_mask
            ).network())

        return ipcalc.Network(next_pos, mask=out_mask)

    except Exception as err:
        raise type(err)('ip_next() error: {}'.format(err))

def ip_prior(ip, in_mask=None, out_mask=None):
    '''
    Identical compliment to ip_next(), but instead of returning next
    ip object, it returns the prior ip object.

    See ip_next() for function interface behavior.

    >>> ip_prior('127.0.0.5')
    Network('127.0.0.4')

    >>> ip_prior('127.0.0.5/24')
    Network('126.255.255.255')

    >>> ip_prior('127.0.0.10/29')
    Network('127.0.0.7')

    >>> ip_prior('1') # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> ip_prior(None) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    ValueError

    >>> ip_prior(['127.0.0.5', '127.0.0.6']) # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
    AttributeError

    '''
    try:
        return ip_next(ip, in_mask, out_mask, _prev=True)
    except Exception as err:
        raise type(err)('ip_prior() error: {}'.format(err))

def redirect(handle=None):
    '''
    Hard redirect for output file handles, stdout/stderr being the primary use.

    Some python modules make assumptions about output that trip us up.
    Use this module to explicitly redirect stdout to stderr, vice-versa.
    This does not handle any other file handles.

    Args:
        None, when called alone, resets all output to runtime defaults.

        fhandle, string: 'stderr' or 'stdout'

    Returns:
        Redirects output to named file handle.
        This function returns nothing else to the caller.
    '''
    try:
        if handle is None:
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
        elif handle is 'stderr':
            sys.stdout = sys.__stderr__
            sys.stderr = sys.__stderr__
        elif handle is 'stdout':
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stdout__
        else:
            msg="Output may be mangled, redirect() expected 'stderr' or 'stdout' but got : '{}'".format(handle)
            print msg
    except Exception as err:
        raise type(err)(
            'redirect() error: {}'.format(err))

##############################################################################
#
class configDict(dict):
    '''
    A convenience object to provide terse variable expansion semantics
    without interrupting runtime.  Behaves like a dict, but when queried,
    does not barf when a key does not exist.

    configDict objects behave identical to dicts in most ways, python
    documentation for working with dict objects covers their use.

    Most importantly, when querying a configDict object for a key which does
    not exist, '' (empty string) is returned instead of raising 'KeyError'.
    This is done without needing any if/try has_key() logic in your program.

    Various "Empty" values return as an empty string, '', which is advantageous
    over returning `None` when handling various config variables, which are often
    mostly strings.  `None` tends to end up being coerced to the string 'None',
    often polluting the actual variable pools being handled.

    configDict functionality is analogous to variable Expansion and Substitution
    found in functional languages like bourne sh(1) shells, awk(1), make(1),
    and the like.


    ## GET OR SET A VARIABLE (just like a dict),
      >> c['foo'] = 'Foo'
      >> c['foo']
      'Foo'

        Just like any dict, nuff said.

        >>> conf = configDict()
        >>> conf['one'] = 1
        >>> conf['two'] = 'Two'
        >>> conf['three'] = 'Three'
        >>> print conf
        {'three': 'Three', 'two': 'Two', 'one': 1}
        >>> print conf['nonexistent']
        <BLANKLINE>


    A description of each configDict behavior beyond being a regular dict:

    ## GET A VARIABLE
     >> c['foo']

        Most important, when querying a configDict object for a key which does
        not exist, '' (empty string) is returned instead of raising 'KeyError'.
          >> c = configDict()
          >> c['foo']
          ''

        Also, both dict as well as object syntax can be used for query, e.g.:
          >> c = configDict()
          >> c['foo'] = 'Foo'
          >> c.foo         # object style get (can collide with object method names)
          'Foo'
          >> c['foo']      # dict style get
          'Foo'
          >> c.get('foo')  # method style get
          'Foo'

        Multiple interface behavior and freedom may prove cumbersome, insomuch as object
        methods would disallow querying keys named, for example, 'copy', (which would
        collide with the dict method 'copy()'), but may resonate with the setter/getter
        crowd.
        Purpose: To return a value and not break runtime if the variable is undefined.
        sh(1) equivalent: $var or ${var}

        >>> conf = configDict()
        >>> conf['foo'] = 'Foo'
        >>> conf.foo
        'Foo'
        >>> conf['foo']
        'Foo'
        >>> conf.get('foo')
        'Foo'


    ## GET, OR RETURN ALTERNATE
      >> c.alt('var', 'thing')

        If `var` exists and isn't null, return it's value; otherwise, return thing,
        `var` remains unchanged.

          >> c.alt('var', 'thing')

        Purpose: To return a default value if the variable is undefined.
        Example: c.alt('count', 0) evaluates to 0 if count is undefined.
        sh(1) equivalent: ${var:-thing} or ${var-thing}

        >>> conf = configDict()
        >>> conf.alt('var', 'thing')
        'thing'
        >>> conf['var'] = 'now contains actual string var'
        >>> conf.alt('var', 'thing')
        'now contains actual string var'


    ## GET, OR SET ALTERNATE
      >> c.alt_set('var', 'thing')

        If `var` exists and isn't null, return it's value; otherwise set it to `thing`
        and return its value.
        Purpose: To set a variable to a default value if it is undefined.
        Example: c.alt('count', 0) sets count to 0 if it is undefined.
        sh(1) equivalent: ${var:=thing}

        >>> conf = configDict()
        >>> conf.alt_set('var', 'thing')
        'thing'
        >>> conf.keys()
        ['var']
        >>> conf['var']
        'thing'


    ## GET, OR BAIL IF NONEXISTENT
      >> c.get_bail('var', "message")

        If var exists and isn't null, return it's value; otherwise, raise `KeyError` and
        return 'var: message' in the error output.
        Omitting message produces the default message '' (empty string).

        Purpose: To catch errors that result from variables being undefined.
        Example: c.get_bail('count', "undefined!") prints 'count: undefined!' and exits
        if count is undefined.
        sh(1) equivalent: ${var:?message}

        >>> conf = configDict()
        >>> conf.get_bail('var', "message") # doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
        KeyError: 'var: message'


    ## RETURN ALT IF EXISTS, OR RETURN NONE
      >> c.get_none('var', 'value')

        If `var` exists and isn't empty, return `value`; otherwise, return empty string,
        `var` remains unchanged.

        Purpose: To test for the existence of a variable.
        Example: c.get_none('count', '1'} returns 1 (which could mean "true")
        if count is defined.
        sh(1) equivalent: ${var:+value}

        >>> conf = configDict()
        >>> conf.get_none('var', 1)
        ''
        >>> conf['again'] = 2
        >>> conf.get_none('again', 2)
        2
        >>> conf.get_none('again', 1)
        ''

    TODO: break this out when slicing up the library, consolidating
    all non-aws configuration loading with it.
    '''
    try:
        def __setitem__(self, key, item):
            self.__dict__[key] = item
        def __getitem__(self, key):
            if self.__dict__.has_key(key):
                return self.__dict__[key]
            else:
                return ''
        def get(self, key):
            if self.__dict__.has_key(key):
                return self.__dict__[key]
            else:
                return ''
        def get_none(self, key, expected):
            if self.__dict__.get(key) is expected:
                return self.__dict__[key]
            else:
                return ''
        def __getattr__(self, key):
            return ''
        def __repr__(self):
            return repr(self.__dict__)
        def __delitem__(self, key):
            del self.__dict__[key]
        def alt(self, key, alt=''):
            if self.__dict__.has_key(key):
                return self.__dict__[key]
            else:
                return alt
        def alt_set(self, key, alt=''):
            if self.__dict__.has_key(key):
                return self.__dict__[key]
            else:
                self.__dict__[key] = alt
                return alt
        def get_bail(self, key, altmsg=''):
            if self.__dict__.has_key(key):
                return self.__dict__[key]
            else:
                msg = "{0}: {1}".format(key, altmsg)
                raise KeyError(msg)
        def alt_if(self, key, alt=''):
            if self.__dict__.has_key(key):
                return alt
            else:
                return ''
        def clear(self):
            return self.__dict__.clear()
        def copy(self):
            return self.__dict__.copy()
        def has_key(self, k):
            return k in self.__dict__
        def update(self, *args, **kwargs):
            return self.__dict__.update(*args, **kwargs)
        def keys(self):
            return self.__dict__.keys()
        def values(self):
            return self.__dict__.values()
        def items(self):
            return self.__dict__.items()
        def pop(self, *args):
            return self.__dict__.pop(*args)
        def __cmp__(self, dict_):
            return self.__cmp__(self.__dict__, dict_)
        def __contains__(self, item):
            return item in self.__dict__
        def __iter__(self):
            return iter(self.__dict__)
        def __unicode__(self):
            return unicode(repr(self.__dict__))
    except Exception as err:
        raise type(err)('class vicConfig(): {}'.format(err))
#
##############################################################################

def main(argv):
    '''
    Designed to be called by wrapper libraries in other languages, providing
    a consistent tooling interface to these library routines.

    This function requires the first arg to be the string name of a function
    in this program.

    Args:
        argv, sys.argv global context.
        First arg must match a function name in this library, the following
        args should match that function's input args or kwargs.

    Returns:
        Function output as JSON for every case.
        Error conditions returned for missing function name, or boiled up
        from the actual function result.
    '''
    import json

    try:
        debug("TODO: this will allow calling py lib from wrappers.")
        debug('Argument List: {0}'.format(str(argv)))
        debug(globals())

        # identify the function we are calling as first arg,
        funk_name = argv.pop(0)
        debug('func_name = {0}'.format(funk_name))
        live_funk = globals()[funk_name]

    except Warning as war:
        print >> sys.stderr, "Input Warning vic lib: {}".format(war)
    except KeyError as err:
        raise KeyError("{} does not exist in vic library".format(str(err)))
    except Exception as err:
        raise type(err)("Input Error vic lib: {}".format(err))

    try:
        # call the actual function
        print json.dumps(live_funk(*argv), indent=1,)

    except Warning as war:
        print >> sys.stderr, 'vic lib runtime warning: {}'.format(war)
    except Exception as err:
        raise type(err)('vic lib runtime error: {}'.format(err))

if __name__ == '__main__':
    main(sys.argv[1:])

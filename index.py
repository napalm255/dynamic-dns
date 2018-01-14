#!/usr/bin/env python
"""Dynamic DNS."""
# pylint: disable=broad-except

from __future__ import print_function
import sys
import logging
import json
from datetime import datetime
from ipaddress import ip_address
import hashlib
from urllib.parse import parse_qsl
import boto3


# logging configuration
logging.getLogger().setLevel(logging.INFO)

try:
    SSM = boto3.client('ssm')

    PREFIX = '/ddns/config'
    PARAMS = SSM.get_parameters_by_path(Path=PREFIX, Recursive=True, WithDecryption=True)
    logging.debug('ssm: parameters (%s)', PARAMS)

    CONFIG = dict()
    for param in PARAMS['Parameters']:
        key = param['Name'].replace('%s/' % PREFIX, '')
        CONFIG.update({key: param['Value']})
    logging.debug('ssm: config (%s)', CONFIG)
    logging.info('ssm: successfully gathered parameters')
except Exception as ex:
    logging.error('ssm: could not connect. (%s)', ex)
    sys.exit()

try:
    R53 = boto3.client('route53')
except Exception as ex:
    logging.error('r53: could not connect. (%s)', ex)
    sys.exit()

try:
    API = boto3.client('apigateway')
except Exception as ex:
    logging.error('apigateway: could not connect. (%s)', ex)
    sys.exit()


def header():
    """Return header object."""
    return {'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'}


def error(message, code=403):
    """Return error object."""
    output = {'statusCode': code,
              'body': json.dumps({'status': 'ERROR',
                                  'message': message}),
              'headers': header()}
    logging.error(output)
    return output


def customer(apikey):
    """Get customer data from api key."""
    token = None
    paginator = API.get_paginator('get_api_keys')
    response = paginator.paginate(includeValues=True,
                                  PaginationConfig={'PageSize': 10})
    data = None
    for res in response:
        for item in res['items']:
            if item['value'] == apikey:
                data = '|'.join([item['name'], item['description']])
                token = hashlib.sha256(bytearray(data, 'utf-8')).hexdigest()
    logging.debug('customer: %s (%s)', token, data)
    return token


def reserved(record):
    """Exclude record names."""
    response = False
    rsrv = list()
    if 'reserved' in CONFIG:
        rsrv = ','.split(CONFIG['reserved'])
    if record in rsrv:
        response = True
    logging.debug('reserved: %s', response)
    return response


def update(token, record, value, ttl=30):
    """Update route 53 record."""
    timestamp = datetime.utcnow().isoformat()
    record = '%s.%s' % (record, CONFIG['domain'])
    response = R53.change_resource_record_sets(
        HostedZoneId=CONFIG['hosted_zone_id'],
        ChangeBatch={
            'Comment': 'ddns',
            'Changes': [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': record,
                        'Type': 'TXT',
                        'TTL': ttl,
                        'ResourceRecords': [
                            {
                                'Value': '"id=%s;ts=%s"' % (token, timestamp)
                            }
                        ]
                    }
                },
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': record,
                        'Type': 'A',
                        'TTL': ttl,
                        'ResourceRecords': [
                            {
                                'Value': value
                            }
                        ]
                    }
                }
            ]
        }
    )
    logging.debug('update: %s', response)
    return response


def authorize(record, token):
    """Authorize route 53 record access."""
    record = '%s.%s' % (record, CONFIG['domain'])
    response = R53.list_resource_record_sets(
        HostedZoneId=CONFIG['hosted_zone_id'],
        StartRecordName=record,
        StartRecordType='TXT'
    )
    logging.debug('authorize: %s', response)
    records = dict()
    for rec in response['ResourceRecordSets']:
        name = '%s|%s' % (rec['Name'].rstrip('.'), rec['Type'])
        value = rec['ResourceRecords'][0]['Value'].strip('"')
        records.update({name: value})
    logging.debug('authorize: records (%s)', records)

    rectype = '%s|TXT' % (record)
    if rectype not in records:
        return True
    if token in records[rectype]:
        return True

    return False


def handler(event, context):
    """Lambda handler."""
    # pylint: disable=unused-argument
    logging.info(event)

    # read event headers
    headers = dict((k.lower(), v) for k, v in event['headers'].items())

    # load data
    try:
        # content-type
        ctype = 'application/x-www-form-urlencoded'
        assert ctype in headers['content-type'].lower(), 'invalid content-type'
        data = dict(parse_qsl(event['body']))
        # validate name
        assert 'name' in data, 'no name provided'
        name = data['name']
        assert not reserved(name), 'name is reserved'
        # validate ip
        assert 'requestContext' in event, 'event error'
        assert 'identity' in event['requestContext'], 'event error'
        assert 'sourceIp' in event['requestContext']['identity'], 'no source ip'
        addy = event['requestContext']['identity']['sourceIp']
        assert ip_address(addy), 'invalid source ip address'
        # check ip override
        if 'ip' in data:
            addy = data['ip']
            assert ip_address(addy), 'invalid override ip address'
    except (ValueError, AssertionError) as ex:
        return error(str(ex))
    except Exception as ex:
        return error('unexpected error loading data (%s)' % ex)

    # authorize and update
    try:
        token = customer(headers['x-api-key'])
        assert token is not None, 'invalid token'
        assert authorize(name, token), 'unauthorized'
        assert update(token, name, addy), 'update failed'
    except AssertionError as ex:
        return error(str(ex))
    except Exception as ex:
        return error('unexpected error updating (%s)' % ex)

    output = {'statusCode': 200,
              'body': json.dumps({'status': 'OK',
                                  'name': name,
                                  'ip': addy}),
              'headers': header()}
    logging.info(output)
    return output


if __name__ == '__main__':
    KEY = sys.argv[1]
    BODY = sys.argv[2]
    print(BODY)
    print(handler({'headers': {'x-api-key': KEY,
                               'Content-Type':
                               'application/x-www-form-urlencoded'},
                   'requestContext': {'identity': {'sourceIp': '6.9.6.9'}},
                   'body': BODY}, None))

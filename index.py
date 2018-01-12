#!/usr/bin/env python
"""Dynamic DNS."""
# pylint: disable=broad-except

from __future__ import print_function
import sys
import logging
import json
import hashlib
from urllib.parse import parse_qsl
import boto3


# logging configuration
logging.getLogger().setLevel(logging.DEBUG)

try:
    SSM = boto3.client('ssm')

    PREFIX = '/ddns/config'
    PARAMS = SSM.get_parameters_by_path(Path=PREFIX, Recursive=True,
                                        WithDecryption=True)
    logging.debug('ssm: parameters (%s)', PARAMS)

    CONFIG = dict()
    for param in PARAMS['Parameters']:
        key = param['Name'].replace('%s/' % PREFIX, '')
        CONFIG.update({key: param['Value']})
    logging.debug('ssm: config (%s)', CONFIG)

    logging.info('ssm: successfully gathered parameters')
except Exception as ex:
    logging.error('ssm: could not connect to SSM. (%s)', ex)
    sys.exit()

try:
    R53 = boto3.client('route53')
except Exception as ex:
    logging.error('r53: could not connect to R53. (%s)', ex)
    sys.exit()


def error(message, header=None, code=403):
    """Return error object."""
    logging.info('handler: error')
    if not header:
        header = {'Content-Type': 'application/json',
                  'Access-Control-Allow-Origin': '*'}
    logging.error('%s (%s)', message, header)
    return {'statusCode': code,
            'body': json.dumps({'status': 'ERROR',
                                'message': message}),
            'headers': header}


def reserved(record):
    """Exclude record names."""
    rsrv = list()
    if 'reserved' in CONFIG:
        rsrv = ','.split(CONFIG['reserved'])
    if record in rsrv:
        return True
    return False


def update(record, addy, auth):
    """Update route 53 record."""
    record = '%s.%s' % (record, CONFIG['domain'])
    token = hashlib.sha256(bytearray(auth, 'utf-8')).hexdigest()
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
                        'TTL': 30,
                        'ResourceRecords': [
                            {
                                'Value': '"%s"' % (token)
                            }
                        ]
                    }
                },
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': record,
                        'Type': 'A',
                        'TTL': 30,
                        'ResourceRecords': [
                            {
                                'Value': addy
                            }
                        ]
                    }
                }
            ]
        }
    )
    return response


def authorize(record, auth):
    """Authorize route 53 record access."""
    record = '%s.%s' % (record, CONFIG['domain'])
    token = hashlib.sha256(bytearray(auth, 'utf-8')).hexdigest()
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
    if token not in records[rectype]:
        return False

    return True


def handler(event, context):
    """Lambda handler."""
    # pylint: disable=unused-argument, too-many-locals, too-many-return-statements
    logging.info(event)

    header = {'Content-Type': 'application/json'}

    # read event headers
    headers = dict((k.lower(), v) for k, v in event['headers'].items())

    # load data
    try:
        assert 'application/x-www-form-urlencoded' in headers['content-type'].lower()
        data = dict(parse_qsl(event['body']))
        logging.debug('data (%s)', data)
    except AssertionError:
        message = 'invalid content-type: %s' % headers['content-type'].lower()
        return error(message, header)

    # selected ip address
    try:
        if 'ip' in data:
            addy = data['ip']
        else:
            addy = event['requestContext']['identity']['sourceIp']
        logging.debug('ip address: %s', addy)
    except KeyError as ex:
        message = 'invalid ip address: %s' % ex
        return error(message)

    # check if record name is reserved
    try:
        assert not reserved(data['name'])
    except AssertionError:
        return error('name is reserved')
    except Exception as ex:
        message = 'unexpected error checking name reservations: %s' % ex
        return error(message)

    # authorize record update
    try:
        assert authorize(data['name'], headers['x-api-key'])
    except AssertionError:
        return error('unauthorized')
    except Exception as ex:
        message = 'unexpected error authorizing record: %s' % ex
        return error(message)

    # update record
    try:
        response = update(data['name'], addy, headers['x-api-key'])
        logging.debug('update: %s', response)
    except Exception as ex:
        message = 'unexpected error updating record: %s' % ex
        return error(message)

    return {'statusCode': 200,
            'body': json.dumps({'status': 'OK'}),
            'headers': header}


if __name__ == '__main__':
    print(handler({'headers': {'x-api-key': 'abcdef0987654321',
                               'Content-Type': 'application/x-www-form-urlencoded',
                               'Origin': '6.9.6.9'},
                   'body': 'name=test'}, None))

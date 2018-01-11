#!/usr/bin/env python
"""Dynamic DNS."""
# pylint: disable=broad-except

from __future__ import print_function
import sys
import logging
import json
import boto3


# logging configuration
logging.getLogger().setLevel(logging.INFO)

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


def handler(event, context):
    """Lambda handler."""
    # pylint: disable=unused-argument, too-many-locals
    logging.info(event)

    header = {'Content-Type': 'application/json'}

    return {'statusCode': 200,
            'body': json.dumps({'status': 'OK'}),
            'headers': header}


if __name__ == '__main__':
    print(handler({'message': ''}, None))

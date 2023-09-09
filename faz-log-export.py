#!/usr/bin/env python3
import os
import sys
import re
import argparse
import json
import time
from datetime import datetime, timedelta
import urllib3
import base64
import hashlib

# Disable Security warnings
urllib3.disable_warnings()


class FortiAPI:
    t_log_map = r'^tlog\.(?P<log_timestamp>\d+)\.log\.gz$'
    tenant_id_map = r'^sc-(?P<tenant_id>\w{4})-(?:[\w-]+)'

    cmd_api = {'login': {'url': '/sys/login/user', 'method': 'exec', 'http': 'post', 'data': True},
               'logout': {'url': '/sys/logout', 'method': 'exec', 'http': 'post', 'data': False},
               'status': {'url': '/sys/status', 'method': 'get', 'http': 'post', 'data': False},
               'adom_get': {'url': '/dvmdb/adom', 'method': 'get', 'http': 'post', 'data': True},
               'adom_get_single': {'url': '/dvmdb/adom/{0}', 'method': 'get', 'http': 'post', 'data': True},
               'adom_get_device': {'url': '/dvmdb/adom/{0}/device', 'method': 'get', 'http': 'post', 'data': True},
               'logfiles_state': {'url': '/logview/adom/{0}/logfiles/state', 'method': 'get', 'http': 'post', 'data': True},
               'logfiles_data': {'url': '/logview/adom/{0}/logfiles/data', 'method': 'get', 'http': 'post', 'data': True},
               'logstat': {'url': '/logview/adom/{0}/logstats', 'method': 'get', 'http': 'post', 'data': True}
               }
    max_chunk_size = 52428800

    def __init__(self, faz_url):
        self.debug = False
        self.dryrun = False
        self.session = ''       # session token
        self.id = 0             # query/request id for api call
        self.faz = faz_url
        self.http_header = {'User-Agent': 'Python Script',
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                            }

        self.t_log_re = re.compile(self.t_log_map, re.IGNORECASE)
        self.tenant_id_re = re.compile(self.tenant_id_map, re.IGNORECASE)

    def api_call(self, api: str, data: dict = {}):
        self.id += 1
        params = {'id': self.id,
                  'jsonrpc': '2.0',
                  'method': self.cmd_api[api]['method'],
                  'session': self.session,
                  'params': [{'url': self.cmd_api[api]['url']}]
                  }

        # append parameters for api call if "data" flag is set
        if self.cmd_api[api]['data']:
            last_index = len(params['params']) - 1
            params['params'][last_index].update(data)

        if self.debug:
            print('> REQUEST: ', params)

        # do a call
        encoded_data = json.dumps(params).encode('utf-8')
        http = urllib3.PoolManager(cert_reqs='CERT_NONE')
        try:
            request = http.request(self.cmd_api[api]['http'].upper(), 'https://{0}/jsonrpc'.format(self.faz),
                                   headers=self.http_header, body=encoded_data)
        except urllib3.exceptions.NewConnectionError:
            print('Connection error', file=sys.stderr)
            exit(1)

        if request.status != 200:
            if self.debug:
                print(request.status, file=sys.stderr)
                print(request.data, file=sys.stderr)
        else:
            try:
                result = json.loads(request.data)
            except json.decoder.JSONDecodeError:
                print('API JSON Error', file=sys.stderr)
                result = {}

        # check status / error code from api
        if 'error' in result.keys() and int(result['error']['code']) < 0:
            result = False

        if self.debug:
            print(json.dumps(result, indent=2))

        return result

    def user_login(self, username: str, password: str):
        params = {'data': {'user': username, 'passwd': password}}

        result = self.api_call('login', params)
        if result['result'][0]['status']['code'] >= 0:
            self.session = result['session']
        return bool(result['result'][0]['status']['code'] >= 0)

    def user_logout(self):
        result = self.api_call('logout')
        return bool(result)

    def get_adom(self, adom: str = ''):
        params = {}
        if adom:
            params['url'] = '{}/{}'.format(self.cmd_api['adom_get']['url'], adom)

        result = self.api_call('adom_get', params)
        if result and bool(result['result'][0]['status']['code'] >= 0):
            return_data = result['result'][0]
        else:
            return_data = False
        return return_data

    def get_adom_single(self, adom):
        params = {}
        pass

    def get_adom_list(self):
        params = {'fields': ['create_time', 'desc', 'name', 'restricted_prds', 'uuid', 'status'],
                  'filter': ['restricted_prds', '==', 1],
                  'range': [0, 500],
                  'sortings': [{'name': 1}]
                  }

        result = self.api_call('adom_get', params)
        if result and bool(result['result'][0]['status']['code'] >= 0):
            return_data = result['result'][0]
        else:
            return_data = False
        return return_data

    def get_adom_devices(self, adom: str):
        params = {'fields': ['desc', 'dev_status', 'hostname', 'ip', 'name'],
                   'range': [0, 500],
                   'sortings': [{'name': 1}],
                   'url': self.cmd_api['adom_get_device']['url'].format(adom)
                  }

        result = self.api_call('adom_get_device', params)
        return bool(result['result'][0]['status']['code'] >= 0)

    def get_logfile_state(self, adom: str, devid: str, time_range: dict):
        # validate input params

        #
        return_data = False
        params = {'apiver': 3,
                  'devid': devid,
                  'time-range': {'end': time_range['end'], 'start': time_range['start']},
                  'url': self.cmd_api['logfiles_state']['url'].format(adom)
                  }

        result = self.api_call('logfiles_state', params)
        if len(result['result']['device-file-list']) > 0:
            return_data = result['result']['device-file-list']
        return return_data

    def get_logfile_data(self, adom: str, outpu_dir: str, log_type: str, file_list: dict, file_filter: list, time_range: dict):
        """
        :param adom: name of ADOM
        :param outpu_dir: directory path for output log files
        :param log_type: type of log from FAZ: tlog
        :param file_list: list of logs produced by get_logfile_state
        :param file_filter: fetch only file from that list
        :param time_range: time range, format 'YYYY-mm-dd'
        :return: None
        """
        # as time-range filtering for "get-logfile-state" api call is not working
        # we have to do a workaround and check timestamp of each logfile

        # apply delta 3h for start and end time
        start_time = datetime.timestamp(datetime.strptime(time_range['start'], '%Y-%m-%d %H:%M:%S') - timedelta(hours=3))
        end_time = datetime.timestamp(datetime.strptime(time_range['end'], '%Y-%m-%d %H:%M:%S') + timedelta(hours=3))

        for _vdom_files in file_list['vdom-file-list']:
            # fetch only specific log type
            if log_type in _vdom_files['logfile-list'].keys():
                # check if list of files is not empty
                if len(_vdom_files['logfile-list'][log_type]['files']) > 0:
                    # verify if logfile is in a time range
                    for item in _vdom_files['logfile-list'][log_type]['files']:
                        # check file timestamp
                        start_file = datetime.timestamp(datetime.strptime(item['starttime'], '%Y-%m-%d %H:%M:%S'))
                        end_file = datetime.timestamp(datetime.strptime(item['endtime'], '%Y-%m-%d %H:%M:%S'))
                        if not (start_file >= start_time and end_file <= end_time):
                            continue

                        # retrieve an original timestamp from filename or create one
                        output_timestamp = self.t_log_re.search(item['filename'])
                        if output_timestamp and output_timestamp.group('log_timestamp'):
                            log_date = datetime.fromtimestamp(int(output_timestamp.group('log_timestamp')))
                        else:
                            log_date = datetime.strptime(item['starttime'], '%Y-%m-%d %H:%M:%S')

                        # output dir, format: <OUTPUT DIR>/<ADOM>/<DEVICE NAME>/<DEVICE ID>/<DATE: year/month/day>/
                        output_dir = '{}/{}/{}/{}/{}'.format(outpu_dir,
                                                             str(adom).lower(),
                                                             file_list['device-name'],
                                                             file_list['device-id'],
                                                             log_date.strftime('%Y/%m/%d'))
                        # output filename
                        output_filename = '{}/{}_{}'.format(output_dir,
                                                            log_date.strftime('%Y%m%d-%H%M%S'),
                                                            item['filename'])

                        # in case list provided check file_filter
                        # fetch only files from list (file_filter)
                        if (len(file_filter) > 0) and not (output_filename in file_filter):
                            continue

                        print('[{}] - logfile: {} date: {} - {} size: {}'.format(time.strftime("%H:%M:%S, %d.%m.%Y"),
                                                                                 output_filename,
                                                                                 item['starttime'],
                                                                                 item['endtime'],
                                                                                 item['fsize']), flush=True)

                        if self.dryrun:
                            continue

                        # verify if output directory (full path, with subdir) exists and create if not
                        if not os.path.exists(output_dir):
                            try:
                                os.makedirs(output_dir)
                            except OSError as error:
                                print(' - create dir error: {}'.format(str(error)), file=sys.stderr)
                                exit(1)

                        # check if logfile exists / already downloaded and have the same size
                        # working only for base64 / original Forti formatted file
                        # which is a proprietary format / db file format
                        if os.path.exists(output_filename):
                            if int(item['fsize']) == os.stat(output_filename).st_size:
                                continue

                        self.fetch_file({'vdom-name': _vdom_files['vdom-name'],
                                         'device-id': file_list['device-id'],
                                         'log_filename': item['filename'],
                                         'output_filename': output_filename,
                                         'url': self.cmd_api['logfiles_data']['url'].format(adom)})

                        # check md5sum / but it would work only for forti native log format
                        # hashlib.md5(open('filename.exe','rb').read()).hexdigest()

    def fetch_file(self, input_param: dict):
        # param structure : {'vdom-name': '', 'device-id': '', 'log_filename': '', 'output_filename': '', 'url': '' }
        # create a new output file
        try:
            with open(input_param['output_filename'], 'wb') as fHandler:
                offset = 0
                chunk = 0
                eof_log = False
                # do loop and fetch chunks
                while not eof_log:
                    api_params = {
                        'apiver': 3,
                        'data-type': 'text/gzip/base64',
                        'devid': input_param['device-id'],
                        'filename': input_param['log_filename'],
                        'length': self.max_chunk_size,
                        'offset': offset,
                        'url': input_param['url'],
                        'vdom': input_param['vdom-name']
                    }
                    result = self.api_call('logfiles_data', api_params)
                    if result:
                        if self.debug:
                            print('[{}] - chunk: {} offset: {} length: {} hash: {}'.format(
                                time.strftime("%H:%M:%S, %d.%m.%Y"),
                                chunk,
                                offset,
                                result['result']['length'],
                                result['result']['checksum']))
                        fHandler.write(base64.b64decode(result['result']['data']))
                        offset += int(result['result']['length'])
                        chunk += 1
                    else:
                        eof_log = True
        except IOError as error:
            print(' - create file error: {}'.format(str(error)), file=sys.stderr)

def main():
    cmd_parser = argparse.ArgumentParser(description='Backup FAZ logs')

    # looking for a config file
    config = {}
    config_file = '{}/{}.conf'.format(os.path.dirname(os.path.abspath(__file__)),
                                      os.path.splitext(os.path.basename(__file__))[0])

    # load config
    if os.path.isfile(config_file):
        with open(config_file) as json_file:
            try:
                config = json.load(json_file)[0]
            except Exception as error:
                print(' - config load error: {}'.format(str(error)), file=sys.stderr)
                sys.exit(1)

    cmd_parser.add_argument('-dryrun', required=False, help="Dry run test")
    cmd_parser.add_argument('-adom', required=False, help="ADOM name")
    cmd_parser.add_argument('-device', required=False, help="Device name")

    cmd_parser.add_argument('-dir', required=True, help="Log output directory")
    cmd_parser.add_argument('-date', required=True, type=json.loads, help="Date range")
    cmd_parser.add_argument('-files', required=False, help="List of files to download")

    config.update(vars(cmd_parser.parse_args()))

    list_of_files = []
    if bool(config['files']) and (os.path.isfile(config['files']) and os.stat(config['files']).st_size > 0):
        with open(config['files'], 'r') as fHandler:
            try:
                list_of_files = [line.rstrip() for line in fHandler.readlines()]
            except Exception as error:
                print(' - list load error: {}'.format(str(error)), file=sys.stderr)
                sys.exit(1)

    if not os.path.exists(config['dir']):
        print(' - output dir doesn\'t exist', file=sys.stderr)
        sys.exit(1)

    # verify date format -date '{'start': '%Y-%m-%d', 'end': '%Y-%m-%d'}'
    try:
        datetime.strptime(config['date']['start'], '%Y-%m-%d')
        datetime.strptime(config['date']['end'], '%Y-%m-%d')
    except ValueError:
        print(' - date format error', file=sys.stderr)
        sys.exit(1)

    time_range = {'start': '{} 00:00:00'.format(config['date']['start']),
                  'end': '{} 00:00:00'.format(config['date']['end'])}

    faz_backup = FortiAPI(config['faz'])
    faz_backup.debug = False
    if 'dryrun' in config.keys():
        faz_backup.dryrun = bool(config['dryrun'])

    flLogin = faz_backup.user_login(config['username'], config['password'])
    if flLogin:
        if config['adom']:
            print(' # ADOM: ', config['adom'])
            logfiles = faz_backup.get_logfile_state(config['adom'], '', time_range)
            if logfiles:
                for _log in logfiles:
                    faz_backup.get_logfile_data(config['adom'], config['dir'], 'tlog', _log, list_of_files, time_range)
        else:
            adoms = faz_backup.get_adom_list()
            if len(adoms['data']) > 0:
                for _adom in adoms['data']:
                    # faz_backup.get_adom_devices(_dev['name'])
                    print(' # ADOM: ', _adom['name'], flush=True)
                    logfiles = faz_backup.get_logfile_state(_adom['name'], '', time_range)
                    if logfiles:
                        for _log in logfiles:
                            faz_backup.get_logfile_data(_adom['name'], config['dir'], 'tlog', _log, list_of_files, time_range)

        faz_backup.user_logout()


if __name__ == "__main__":
    main()

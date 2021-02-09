#!/usr/bin/env python3

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json
import time

def login_cpmgmt():
    """A simple function to log in to Check Point Management Server."""

    user = 'admin'
    p = 'vpn123'
    mgmt_ip = '192.168.56.81'

    json_payload = {
                "user": user,
                "password": p
                }

    url = 'https://' + mgmt_ip + '/web_api/login'

    response = requests.post(url, json=json_payload, verify=False)
    response_json = response.json()
    
    if response.status_code == 200:
        print('Login to Check Point MGMT Server was Successful - {}'.format(url))    
        return response_json['sid']

    else:
        print('Login to Check Point MGMT Server was unsuccessful. Error code: {}.'.format(response.status_code))
        return response

def cp_publish(sid):
    """A simple function to publish changes to mangement sever. Takes one argument: sid"""
    json_payload = {}

    mgmt_ip = '192.168.56.81'

    url = 'https://' + mgmt_ip + '/web_api/publish'
    
    request_headers = {'Content-Type': 'application/json',
                        'X-chkp-sid': sid,
                     }

    response = requests.post(url, json=json_payload, headers=request_headers, verify=False)

    if response.status_code == 200:
        print('Check Point API Call Success - Command publish')
        print('Waiting 15 seconds')
        time.sleep(15)
    else:
        print('Publish was unsuccessful. Error code: {}.'.format(response.status_code))

    return response

def cp_api_call(command, json_payload, sid):

    mgmt_ip = '192.168.56.81'

    url = 'https://' + mgmt_ip + '/web_api/' + command

    if sid == '':
        request_headers = {'Content-Type' : 'application/json'}
    else:
        request_headers = {'Content-Type' : 'application/json', 'X-chkp-sid' : sid}


    r = requests.post(url,data=json.dumps(json_payload), headers=request_headers, verify=False)

    if r.status_code != 200:
        print('Check Point API Call Error! - Command {} failed!'.format(command))
    else:
        print('Check Point API Call Success - Command {}'.format(command))

def get_rule_info():

    rule = dict()
    rule['src'] = input('src (name): ')
    rule['dst'] = input('dst (name): ')
    rule['service'] = input('service (name): ')
    rule['action'] = input('action: ')
    rule['tag'] = input('tag: ')

    return rule

def create_rule(sid, rule):

    json_payload = {
                      "layer" : "vattenfall-policy Network",
                      "position" : {
                        "bottom" : rule['tag']
                      },
                      #"name" : "test",
                      'source' : rule['src'],
                      "destination" : rule['dst'],
                      "service" : rule['service'],
                      "action" : rule['action'],
                      #"comments" : comment
                    }

    cp_api_call('add-access-rule', json_payload, sid)

def take_action():

    sid = login_cpmgmt()
    rule = get_rule_info()
    create_rule(sid, rule)
    cp_publish(sid)
    cp_api_call('logout', {}, sid)

if __name__ == '__main__':
    take_action()

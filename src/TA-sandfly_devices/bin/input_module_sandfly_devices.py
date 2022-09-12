
# encoding = utf-8

import json
from Sandfly import Sandfly
from sandfly_utils import *

'''
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
'''
'''
# For advanced users, if you want to create single instance mod input, uncomment this method.
def use_single_instance_mode():
    return True
'''


def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # global_account = definition.parameters.get('global_account', None)
    pass


def collect_events(helper, ew):
    log_level = helper.get_log_level()
    helper.set_log_level(log_level)
    helper.log_info(f'msg="logging level set", log_level="{log_level}"')

    global_account = helper.get_arg('global_account')
    hostname = global_account['hostname']
    username = global_account['username']
    password = global_account['password']
    ca_cert = global_account['ca_cert']
    verify_cert = global_account['verify_cert']
    sourcetype = helper.get_sourcetype()
    host_summary = helper.get_arg('host_summary')

    if host_summary:
        sourcetype = sourcetype + ":summary"

    stanza = str(helper.get_input_stanza_names())

    proxy = helper.get_proxy()
    event_type = 'proxy_config'
    if proxy:
        if proxy["proxy_username"]:
            event_log = sf_logger(
                msg='Proxy is configured with authentication',
                action='success',
                event_type=event_type,
                stanza=stanza,
                hostname=hostname
            )
            helper.log_info(event_log)

        else:
            event_log = sf_logger(
                msg='Proxy is configured with no authentication',
                action='success',
                event_type=event_type,
                stanza=stanza,
                hostname=hostname
            )
            helper.log_info(event_log)

        proxy_config = True
    else:
        proxy_config = False

    def get_hosts():
        event_type = 'input_get_hosts'

        # Check if it is time to run
        if not checkpointer(helper, hostname, stanza):
            return False

        event_log = sf_logger(
            msg='Starting event collection',
            action='started',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname
        )
        helper.log_info(event_log)

        sandfly = Sandfly(
            username=username,
            password=password,
            hostname=hostname,
            ca_cert=ca_cert,
            verify_cert=verify_cert,
            use_proxy=proxy_config
        )

        result, token_message = sandfly.get_token(helper, stanza)
        if result == 'success':
            event_log = sf_logger(
                msg='Retrieved token',
                action='success',
                event_type=event_type,
                stanza=stanza,
                hostname=hostname
            )
            helper.log_info(event_log)
        else:
            helper.log_error(token_message)
            return False

        result, hosts_message = sandfly.get_hosts(helper, stanza, host_summary)
        if result == 'success':
            event_log = sf_logger(
                msg='Retrieved hosts',
                action='success',
                event_type=event_type,
                stanza=stanza,
                hostname=hostname
            )
            helper.log_info(event_log)
            host_data = hosts_message
        else:
            helper.log_error(hosts_message)
            return False

        event_count = 0
        for data in host_data['data']:
            data['host_summary'] = host_summary
            event = helper.new_event(
                source=helper.get_input_type(),
                index=helper.get_output_index(),
                sourcetype=sourcetype,
                data=json.dumps(data),
                host=hostname
            )
            ew.write_event(event)
            event_count += 1

        event_log = sf_logger(
            msg='Completed host ingestion',
            action='success',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname,
            event_count=event_count
        )
        helper.log_info(event_log)

        # Checkpointer
        checkpointer(helper, hostname, stanza, setCheckpoint=True)

        result, message = sandfly.logout(helper, stanza)
        if result == 'success':
            event_log = sf_logger(
                msg='Logged out',
                action='success',
                event_type=event_type,
                stanza=stanza,
                hostname=hostname
            )
            helper.log_info(event_log)
        else:
            helper.log_error(message)
            return False

    get_hosts()

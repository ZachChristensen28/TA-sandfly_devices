import sandfly_constants as const
from sandfly_utils import *

# TEMP
import json


class SandflyAuth:
    """
    Handles authentication to Sandfly
    """

    def __init__(self, username, password, hostname, ca_cert, verify_cert, use_proxy):
        self.username = username
        self.password = password
        self.hostname = hostname.rstrip('/')
        self.ca_cert = ca_cert
        self.use_proxy = use_proxy
        self.token = None
        self.checkCert = None

        if ca_cert:
            if verify_cert == '1':
                self.checkCert = True
            else:
                self.verify = False
        else:
            if verify_cert == '1':
                self.verify = True
            else:
                self.verify = False

    def get_token(self, helper, stanza):
        event_type = 'get_token'
        event_log = sf_logger(
            msg='Fetching token',
            action='started',
            event_type=event_type,
            stanza=stanza,
            hostname=self.hostname
        )
        helper.log_info(event_log)

        headers = {'content-type': 'application/json',
                   'accept': 'application/json', 'user-agent': 'Splunk-ta-sandfly-devices'}
        payload = {'username': self.username,
                   'password': self.password, 'full_details': False}
        url = f'https://{self.hostname}/{const.sandfly_login}'
        cert = None

        if self.checkCert:
            cert = check_cert(helper, stanza=stanza,
                              cert=self.ca_cert, hostname=self.hostname)

        if cert:
            self.verify = cert

        result, response_message = sendit(
            helper,
            url,
            method='POST',
            verify=self.verify,
            use_proxy=self.use_proxy,
            stanza=stanza,
            hostname=self.hostname,
            headers=headers,
            payload=payload
        )

        if result == 'success':
            response = response_message
            if 'access_token' in list(response.keys()):
                self.token = response['access_token']
                result = 'success'
                return result, None

            else:
                result = 'failure'
                message = sf_logger(
                    msg=response['title'],
                    action='failure',
                    event_type=event_type,
                    stanza=stanza,
                    hostname=self.hostname,
                    http_status_code=response['status'],
                    details=response['detail']
                )
                return result, message
        else:
            return result, response_message

    def get_hosts(self, helper, stanza, host_summary):
        event_type = 'get_hosts'
        event_log = sf_logger(
            msg='Fetching hosts',
            action='started',
            event_type=event_type,
            stanza=stanza,
            hostname=self.hostname
        )
        helper.log_info(event_log)

        url = f'https://{self.hostname}/{const.sandfly_hosts}'

        if host_summary:
            event_log = sf_logger(
                msg='Host collection set to summaries only',
                action='success',
                event_type=event_type,
                stanza=stanza,
                hostname=self.hostname,
                host_summary=host_summary
            )
            helper.log_info(event_log)
            params = {'summary': 'true'}
        else:
            event_log = sf_logger(
                msg='Host collection set to all',
                action='success',
                event_type=event_type,
                stanza=stanza,
                hostname=self.hostname,
                host_summary=host_summary
            )
            helper.log_info(event_log)
            params = {'summary': 'false'}

        headers = {
            'content-type': 'application/json',
            'accept': 'application/json',
            'user-agent': 'Splunk-ta-sandfly-devices',
            'Authorization': 'Bearer {}'.format(self.token)
        }

        result, response_message = sendit(
            helper,
            url,
            method='GET',
            verify=self.verify,
            use_proxy=self.use_proxy,
            headers=headers,
            stanza=stanza,
            hostname=self.hostname,
            parameters=params
        )

        if result == 'success':
            response = response_message
            if 'data' in list(response.keys()):
                result = 'success'
                hosts = response
                return result, hosts

            else:
                result = 'failure'
                message = sf_logger(
                    msg=response['title'],
                    action='failure',
                    event_type=event_type,
                    stanza=stanza,
                    hostname=self.hostname,
                    http_status_code=response['status'],
                    details=response['detail']
                )
                return result, message
        else:
            return result, response_message

    def logout(self, helper, stanza):
        event_type = 'logout'
        event_log = sf_logger(
            msg='Logging out',
            action='started',
            event_type=event_type,
            stanza=stanza,
            hostname=self.hostname
        )
        helper.log_info(event_log)

        headers = {
            'content-type': 'application/json',
            'accept': 'application/json',
            'user-agent': 'Splunk-ta-sandfly-devices',
            'Authorization': 'Bearer {}'.format(self.token)
        }
        url = f'https://{self.hostname}/{const.sandfly_logout}'

        result, response_message = sendit(
            helper,
            url,
            method='DELETE',
            verify=self.verify,
            use_proxy=self.use_proxy,
            headers=headers,
            stanza=stanza,
            hostname=self.hostname
        )

        if result == 'success':
            return result, None

        else:
            return result, response_message

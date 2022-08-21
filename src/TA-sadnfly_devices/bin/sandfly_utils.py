from hashlib import md5
from os import path, environ
from requests.exceptions import HTTPError
import time
import json


def check_cert(helper, cert, stanza, hostname):
    """ Check for valid certificate

    :param helper: addon builder helper
    :param cert: Certificate path
    :param stanza: valid input stanza
    :param hostname: IP/FQDN
    """
    event_type = 'certificate'
    app_name = helper.get_app_name()

    if path.isfile(cert):
        cert_status = 'success'
        cert_path = cert

    elif path.isfile(path.join(path.join(environ['SPLUNK_HOME'], 'etc', 'auth'), cert)):
        cert_status = 'success'
        cert_path = path.join(
            path.join(environ['SPLUNK_HOME'], 'etc', 'auth'), cert)

    elif path.isfile(path.join(path.join(environ['SPLUNK_HOME'], 'etc', 'apps', app_name, 'local'), cert)):
        cert_status = 'success'
        cert_path = path.join(path.join(
            environ['SPLUNK_HOME'], 'etc', 'apps', app_name, 'local'), cert)

    else:
        cert_status = 'failure'

    if cert_status == 'success':
        event_log = sf_logger(
            msg='Certificate found',
            action='success',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname,
            cert=cert_path
        )
        helper.log_info(event_log)
        return cert_path
    else:
        event_log = sf_logger(
            msg='Certificate not found',
            action='failure',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname,
            cert=cert
        )
        helper.log_error(event_log)
        raise Exception(
            'Missing certificate: {} - Disable certificate checking or add a valid certificate'.format(cert))


def sendit(helper, url, method, verify, use_proxy, stanza, hostname, headers=None, payload=None, parameters=None, timeout=10):
    """ Sends HTTP request

    :param helper: addon builder helper.
    :param url: URL to use in request.
    :param method: HTTP method to use in request.
    :param verify: True/False or a valid CA certificate.
    :param use_proxy: (bool) whether to use proxy settings.
    :param stanza: input stanza.
    :param hostname: IP/FQDN.
    :param headers: (optional) HTTP headers for request.
    :param payload: (optional) HTTP payload for request.
    :param parameters: (optional) HTTP parameters for request.
    :param timeout: (optional) connection timeout. Defaults to 10.
    """
    event_type = 'http_request'
    event_log = sf_logger(
        msg='Starting HTTP request',
        action='started',
        event_type=event_type,
        stanza=stanza,
        hostname=hostname,
        verify_certificate=verify
    )
    helper.log_info(event_log)

    try:
        r = helper.send_http_request(
            url=url,
            method=method,
            timeout=timeout,
            payload=payload,
            headers=headers,
            parameters=parameters,
            verify=verify,
            use_proxy=use_proxy
        )

        if r.status_code == 200:
            result = 'success'
            response = r.json()
            return result, response
        else:
            result = 'failure'
            message = sf_logger(
                msg='Unable to get token',
                action='failure',
                event_type=event_type,
                stanza=stanza,
                hostname=hostname,
                http_status=r.status_code,
                details=json.dumps(r.json())
            )
            return result, message

    except HTTPError as http_err:
        result = 'failure'
        message = sf_logger(
            msg='HTTP Error',
            action='failure',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname,
            details=http_err
        )
        return result, message

    except Exception as e:
        result = 'failure'
        message = sf_logger(
            msg='Failed to make request',
            action='failure',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname,
            http_status_code=r.status_code,
            details=e
        )
        return result, message


def checkpointer(helper, hostname, stanza, setCheckpoint=False):
    """ Checkpointer

    :param helper: addon builder helper
    :param hostname: IP/FQDN of host
    :param stanza: input stanza
    :param setCheckpoint: (Default False)
    """
    event_type = 'checkpointer'
    interval = helper.get_arg('interval')

    try:
        int(interval)
    except ValueError:
        event_log = sf_logger(
            msg='Checkpointer not needed, using cron',
            action='aborted',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname
        )
        helper.log_info(event_log)
        return True
    else:
        interval = int(interval)

    currentTime = int(time.time())
    checkTime = currentTime - interval + 60
    key = f'{hostname}-{stanza}'
    hKey = md5(key.encode())
    key = hKey.hexdigest()

    if setCheckpoint:
        newState = int(time.time())
        helper.save_check_point(key, newState)
        event_log = sf_logger(
            msg='Updated checkpoint',
            action='success',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname
        )
        helper.log_info(event_log)
        return True

    if helper.get_check_point(key):
        oldState = int(helper.get_check_point(key))
        event_log = sf_logger(
            msg='Checkpoint found',
            action='success',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname
        )
        event_log_debug = sf_logger(
            msg='Checkpoint DEBUG',
            action='success',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname,
            checkpoint_state=oldState,
            interval=interval
        )
        helper.log_info(event_log)
        helper.log_debug(event_log_debug)

        if checkTime < oldState:
            event_log = sf_logger(
                msg='Skipping ingestion',
                action='aborted',
                event_type=event_type,
                stanza=stanza,
                hostname=hostname,
                reason='interval to close to previous run'
            )
            helper.log_info(event_log)
            return False

        else:
            event_log = sf_logger(
                msg='Running scheduled interval',
                action='success',
                event_type=event_type,
                stanza=stanza,
                hostname=hostname
            )
            helper.log_info(event_log)
    else:
        event_log = sf_logger(
            msg='Checkpoint file not found',
            action='success',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname
        )
        helper.log_info(event_log)

    return True


def sf_logger(msg, action, event_type, stanza, hostname, **kwargs):
    """ To help with consistent logging format

    :param msg: message for log
    :param action: event outcome (started|success|failure|aborted)
    :param event_type: type of event
    :param stanza: stanza for event
    :param hostname: hostname of event
    :param kwargs: any kv pair

    sf_logger(
            msg='message',
            action='success',
            event_type=event_type,
            stanza=stanza,
            hostname=hostname
        )
    """
    event_log = f'msg="{msg}", action="{action}", event_type="{event_type}", input_stanza="{stanza}", hostname="{hostname}"'
    for key, value in kwargs.items():
        event_log = event_log + f', {key}="{value}"'

    return event_log

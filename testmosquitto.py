from mosquitto_pyplugin import ffi
from mosquitto_pyplugin import lib as mosquitto_pyplugin
import sys

def log(loglevel, message):
    cstr = ffi.new("char[]", message.encode('UTF8'))
    mosquitto_pyplugin.Log(loglevel, cstr)

def plugin_init(opts):
    log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'plugin_init (opts: %r)' % (opts,)
    )


def plugin_cleanup():
    log(mosquitto_pyplugin.MOSQ_LOG_INFO, 'plugin_cleanup')


def unpwd_check(username, password):
    log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'unpwd_check (username: %s password: %s)' % (username, password)
    )

    return True


def acl_check(client_id, username, topic, access, payload):
    log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'acl_check %r' % (mosquitto_pyplugin.topic_matches_sub('/#', topic))
    )

    if access == mosquitto_pyplugin.MOSQ_ACL_READ:
        log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'acl_check READ (client_id: {} username: {} topic: {} access: {}, payload: {!r})'
            .format(client_id, username, topic, access, payload)
        )
    elif access == mosquitto_pyplugin.MOSQ_ACL_SUBSCRIBE:
        log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'acl_check SUBSCRIBE (client_id: {} username: {} topic: {} access: {}, payload: {!r})'
            .format(client_id, username, topic, access, payload)
        )
    elif access == mosquitto_pyplugin.MOSQ_ACL_WRITE:
        log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'acl_check WRITE (client_id: {} username: {} topic: {} access: {}, payload: {!r})'
            .format(client_id, username, topic, access, payload)
        )
    return True


def psk_key_get(identity, hint):
    log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'psk_key_get (identity: %s hint: %s)' % (identity, hint)
    )
    return '0123456789'


def security_init(opts, reload):
    log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'security_init (reload: %s, opts: %s)' % (reload, opts)
    )


def security_cleanup(reload):
    log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'security_cleanup (reload: %s)' % (reload)
    )

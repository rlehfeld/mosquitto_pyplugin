import mosquitto_pyplugin


def plugin_init(options):
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'plugin_init (options: {})'.format(options)
    )


def plugin_cleanup(options):
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'plugin_cleanup (options: {})'.format(options)
    )


def basic_auth(client_id, username, password):
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'basic_auth (client_id: {} username: {} password: {})'.format(
            client_id, username, password
        )
    )

    return mosquitto_pyplugin.MOSQ_ERR_SUCCESS


def acl_check(client_id, username, topic, access, payload):
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'acl_check {}'.format(
            mosquitto_pyplugin.topic_matches_sub('/#', topic)
        )
    )

    if access == mosquitto_pyplugin.MOSQ_ACL_READ:
        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'acl_check READ (client_id: {} username: {} topic: {} '
            'access: {}, payload: {!r})'
            .format(client_id, username, topic, access, payload)
        )
    elif access == mosquitto_pyplugin.MOSQ_ACL_SUBSCRIBE:
        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'acl_check SUBSCRIBE (client_id: {} username: {} topic: {} '
            'access: {}, payload: {!r})'
            .format(client_id, username, topic, access, payload)
        )
    elif access == mosquitto_pyplugin.MOSQ_ACL_WRITE:
        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'acl_check WRITE (client_id: {} username: {} topic: {} '
            'access: {}, payload: {!r})'
            .format(client_id, username, topic, access, payload)
        )
    return mosquitto_pyplugin.MOSQ_ERR_SUCCESS


def psk_key_get(identity, hint):
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'psk_key_get (identity: {} hint: {})'.format(identity, hint)
    )
    return '0123456789'

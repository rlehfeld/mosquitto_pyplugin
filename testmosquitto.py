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


def basic_auth(client_id, username, password,
               client_address, client_protocol,
               client_protocol_version):
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'basic_auth (client_id: {} username: {} password: {} '
        'client_address: {} client_protocol: {} '
        'client_protocol_version: {})'.format(
            client_id, username, password, client_address, client_protocol,
            client_protocol_version
        )
    )

    return mosquitto_pyplugin.MOSQ_ERR_SUCCESS


def acl_check(client_id, client_username, client_address, client_protocol,
              client_protocol_version, topic, access, payload):
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'acl_check {}'.format(
            mosquitto_pyplugin.topic_matches_sub('/#', topic)
        )
    )

    access_text = None
    if access == mosquitto_pyplugin.MOSQ_ACL_READ:
        access_text = 'READ'
    elif access == mosquitto_pyplugin.MOSQ_ACL_SUBSCRIBE:
        access_text = 'SUBSCRIBE'
    elif access == mosquitto_pyplugin.MOSQ_ACL_WRITE:
        access_text = 'WRITE'
    if access_text:
        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'acl_check {} (client_id: {} client_username: {} '
            'client_address: {} client_protocol: {} '
            'client_protocol_version: {} topic: {} access: {} '
            'payload: {!r})'
            .format(access_text, client_id, client_username, client_address,
                    client_protocol, client_protocol_version, topic, access,
                    payload)
        )
    return mosquitto_pyplugin.MOSQ_ERR_SUCCESS


def psk_key_get(identity, hint):
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'psk_key_get (identity: {} hint: {})'.format(identity, hint)
    )
    return '0123456789'

import mosquitto_pyplugin
import json

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


def basic_auth(client, username, password):
    client_id = mosquitto_pyplugin.client_id(client)
    client_address = mosquitto_pyplugin.client_address(client)
    client_protocol = mosquitto_pyplugin.client_protocol(client)
    client_protocol_version = mosquitto_pyplugin.client_protocol_version(
        client
    )
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


def acl_check(client, topic, access, payload):
    client_id = mosquitto_pyplugin.client_id(client)
    client_username = mosquitto_pyplugin.client_username(client)
    client_address = mosquitto_pyplugin.client_address(client)
    client_protocol = mosquitto_pyplugin.client_protocol(client)
    client_protocol_version = mosquitto_pyplugin.client_protocol_version(
        client
    )
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
            .format(
                access_text, client_id, client_username, client_address,
                client_protocol, client_protocol_version, topic, access,
                payload
            )
        )
    return mosquitto_pyplugin.MOSQ_ERR_SUCCESS


def psk_key(client, hint, identity):
    client_id = mosquitto_pyplugin.client_id(client)
    client_username = mosquitto_pyplugin.client_username(client)
    client_address = mosquitto_pyplugin.client_address(client)
    client_protocol = mosquitto_pyplugin.client_protocol(client)
    client_protocol_version = mosquitto_pyplugin.client_protocol_version(
        client
    )
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'psk_key (client_id: {} client_username: {} '
        'client_address: {} client_protocol: {} '
        'client_protocol_version: {} hint: {} identity: {})'.format(
            client_id, client_username, client_address, client_protocol,
            client_protocol_version, hint, identity
        )
    )
    return '0123456789'


def disconnect(client, reason):
    client_id = mosquitto_pyplugin.client_id(client)
    client_username = mosquitto_pyplugin.client_username(client)
    client_address = mosquitto_pyplugin.client_address(client)
    client_protocol = mosquitto_pyplugin.client_protocol(client)
    client_protocol_version = mosquitto_pyplugin.client_protocol_version(
        client
    )
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'disconnect (client_id: {} client_username: {} '
        'client_address: {} client_protocol: {} '
        'client_protocol_version: {} reason: {})'.format(
            client_id, client_username, client_address, client_protocol,
            client_protocol_version, reason
        )
    )


def message(client, message_event):
    client_id = mosquitto_pyplugin.client_id(client)
    client_username = mosquitto_pyplugin.client_username(client)
    client_address = mosquitto_pyplugin.client_address(client)
    client_protocol = mosquitto_pyplugin.client_protocol(client)
    client_protocol_version = mosquitto_pyplugin.client_protocol_version(
        client
    )

    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        '<<<< message (client_id: {} client_username: {} '
        'client_address: {} client_protocol: {} '
        'client_protocol_version: {} message: {})'.format(
            client_id, client_username, client_address, client_protocol,
            client_protocol_version, message_event
        )
    )

    message_event.retain = False
    if message_event.payload:
        try:
            data = json.loads(message_event.payload)
            data['added_value'] = 4711
            if 'Wifi' in data:
                if 'SSId' in data['Wifi']:
                    data['Wifi']['SSId'] = 'xxxxxxxxx'
                if 'BSSId' in data['Wifi']:
                    del data['Wifi']['BSSId']
            message_event.payload = json.dumps(data)
        except json.decoder.JSONDecodeError:
            pass

    message_event.properties.extend(
        (
            ('user-property', ('prop1', 'value1')),
            ('user-property', ('prop2', 'value2')),
        )
    )

    message_event.topic = f'changed/{message_event.topic}'

    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        '>>>> message (client_id: {} client_username: {} '
        'client_address: {} client_protocol: {} '
        'client_protocol_version: {} message: {})'.format(
            client_id, client_username, client_address, client_protocol,
            client_protocol_version, message_event
        )
    )

    return mosquitto_pyplugin.MOSQ_ERR_SUCCESS

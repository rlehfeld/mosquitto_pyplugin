import mosquitto_pyplugin
import json
import sys
import time
import asyncio
from distutils.util import strtobool


class IntervalTimer:
    def __init__(self, interval, callback):
        self._interval = interval
        self._callback = callback
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        self._task = loop.create_task(self._job())

    async def _job(self):
        while True:
            offset = int(time.time()) % self._interval
            await asyncio.sleep(self._interval - offset)
            await self._callback()

    def cancel(self):
        self._task.cancel()


class Plugin:

    def __init__(self, options):
        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'Plugin.__init__ (options: {})'.format(options)
        )
        self._add_value = options.get('add_value', 4711)
        self._time_of_day = int(options.get('time_of_day', 0))
        self._anonymous_allowed = bool(strtobool(options.get(
            'allow_anonymous',
            'False'
        )))
        if self._time_of_day > 0:
            self.timer = IntervalTimer(self._time_of_day, self.publish_time)

    async def publish_time(self):
        mosquitto_pyplugin.broker_publish(
            'time-of-day',
            None,
            time.asctime(time.gmtime())
        )

    def plugin_cleanup(self, options):
        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'Plugin.plugin_cleanup (options: {})'.format(options)
        )

    def basic_auth(self, client, username, password):
        client_id = mosquitto_pyplugin.client_id(client)
        client_address = mosquitto_pyplugin.client_address(client)
        client_protocol = mosquitto_pyplugin.client_protocol(client)
        client_protocol_version = mosquitto_pyplugin.client_protocol_version(
            client
        )

        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'Plugin.basic_auth (client_id: {} username: {} password: {} '
            'client_address: {} client_protocol: {} '
            'client_protocol_version: {})'.format(
                client_id, username, password, client_address, client_protocol,
                client_protocol_version
            )
        )

        client_certificate = mosquitto_pyplugin.client_certificate(client)
        if client_certificate:
            print(
                'Plugin.basic_auth certificate (client_id: {}):\n{}'.format(
                    client_id, client_certificate
                ),
                file=sys.stderr,
            )

        if ((not username or not password)
                and not self._anonymous_allowed):
            return mosquitto_pyplugin.MOSQ_ERR_AUTH

        return mosquitto_pyplugin.MOSQ_ERR_SUCCESS

    def acl_check(self, client, topic, access, payload):
        client_id = mosquitto_pyplugin.client_id(client)
        client_username = mosquitto_pyplugin.client_username(client)
        client_address = mosquitto_pyplugin.client_address(client)
        client_protocol = mosquitto_pyplugin.client_protocol(client)
        client_protocol_version = mosquitto_pyplugin.client_protocol_version(
            client
        )
        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'Plugin.acl_check {}'.format(
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
                'Plugin.acl_check {} (client_id: {} client_username: {} '
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

    def psk_key(self, client, hint, identity):
        client_id = mosquitto_pyplugin.client_id(client)
        client_username = mosquitto_pyplugin.client_username(client)
        client_address = mosquitto_pyplugin.client_address(client)
        client_protocol = mosquitto_pyplugin.client_protocol(client)
        client_protocol_version = mosquitto_pyplugin.client_protocol_version(
            client
        )
        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'Plugin.psk_key (client_id: {} client_username: {} '
            'client_address: {} client_protocol: {} '
            'client_protocol_version: {} hint: {} identity: {})'.format(
                client_id, client_username, client_address, client_protocol,
                client_protocol_version, hint, identity
            )
        )
        return '0123456789'

    def disconnect(self, client, reason):
        client_id = mosquitto_pyplugin.client_id(client)
        client_username = mosquitto_pyplugin.client_username(client)
        client_address = mosquitto_pyplugin.client_address(client)
        client_protocol = mosquitto_pyplugin.client_protocol(client)
        client_protocol_version = mosquitto_pyplugin.client_protocol_version(
            client
        )
        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'Plugin.disconnect (client_id: {} client_username: {} '
            'client_address: {} client_protocol: {} '
            'client_protocol_version: {} reason: {})'.format(
                client_id, client_username, client_address, client_protocol,
                client_protocol_version, reason
            )
        )

    def message(self, client, message_event):
        client_id = mosquitto_pyplugin.client_id(client)
        client_username = mosquitto_pyplugin.client_username(client)
        client_address = mosquitto_pyplugin.client_address(client)
        client_protocol = mosquitto_pyplugin.client_protocol(client)
        client_protocol_version = mosquitto_pyplugin.client_protocol_version(
            client
        )

        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            '<<<< Plugin.message (client_id: {} client_username: {} '
            'client_address: {} client_protocol: {} '
            'client_protocol_version: {} message: {})'.format(
                client_id, client_username, client_address, client_protocol,
                client_protocol_version, message_event
            )
        )

        time_of_arrival = time.asctime(time.gmtime())

        message_event.retain = False
        if message_event.payload:
            try:
                data = json.loads(message_event.payload)
                data['added_value'] = self._add_value
                data['time-of-arrival'] = time_of_arrival
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
                ('user-property', ('time-of-arrival', time_of_arrival)),
                ('user-property', ('other-property', 'other-value')),
            )
        )

        message_event.topic = f'changed/{message_event.topic}'

        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            '>>>> Plugin.message (client_id: {} client_username: {} '
            'client_address: {} client_protocol: {} '
            'client_protocol_version: {} message: {})'.format(
                client_id, client_username, client_address, client_protocol,
                client_protocol_version, message_event
            )
        )

        return mosquitto_pyplugin.MOSQ_ERR_SUCCESS


def plugin_init(options):
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'plugin_init (options: {})'.format(options)
    )
    return Plugin(options)

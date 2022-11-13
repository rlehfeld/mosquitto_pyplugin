import mosquitto_pyplugin


class Plugin:

    def __init__(self, options):
        self._schedules = {}

        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'Plugin.__init__ (options: {})'.format(options)
        )

    def plugin_cleanup(self, options):
        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'Plugin.plugin_cleanup (options: {})'.format(options)
        )

    def basic_auth(self, client, username, password):
        return mosquitto_pyplugin.MOSQ_ERR_SUCCESS

    def acl_check(self, client, topic, access, payload):
        return mosquitto_pyplugin.MOSQ_ERR_SUCCESS

    def message(self, client, message_event):
        suffix = '/stat/things/thermostat/schedules'
        if (message_event.topic.endswith(suffix) and
                message_event.payload != self._schedules.get(
                    message_event.topic
                )):
            self._schedules[message_event.topic] = message_event.payload
            topic = (message_event.topic[:-len(suffix)] +
                     '/cmnd/things/thermostat/schedules')
            mosquitto_pyplugin.broker_publish(
                None,
                topic,
                message_event.payload,
                2,
                True,
                [],
            )

        if any(message_event.topic.endswith(t) for t in [
                '/cmnd/things/thermostat/properties/deviceOn',
                '/cmnd/things/thermostat/properties/mode',
                '/cmnd/things/thermostat/properties/targetTemperature',
        ]):
            message_event.retain = True

        return mosquitto_pyplugin.MOSQ_ERR_SUCCESS


def plugin_init(options):
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        'plugin_init (options: {})'.format(options)
    )
    return Plugin(options)

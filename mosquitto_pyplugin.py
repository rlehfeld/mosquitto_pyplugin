from _mosquitto_pyplugin import ffi, lib
import importlib


_HANDLER = []


def _from_binary(value, valuelen):
    if value is None or value == ffi.NULL:
        return None
    return bytes(ffi.unpack(ffi.cast('char*', value), valuelen))


def _from_cstr(cstr):
    if cstr is None or cstr == ffi.NULL:
        return None
    else:
        return ffi.string(cstr).decode('utf8')


def _to_binary(value):
    if value is None:
        return ffi.NULL, 0
    elif isinstance(value, str):
        value_binary = value.encode('UTF8')
    else:
        value_binary = bytes(value)
    return ffi.new('char[]', value_binary), len(value)


def _to_cstr(value):
    return _to_binary(value)[0]


def _read_byte_property(property_ptr, property_identifier):
    property_value = ffi.new('uint8_t*')
    property_found_ptr = lib.mosquitto_property_read_byte(
        property_ptr,
        property_identifier,
        property_value,
        False,
    )
    if property_found_ptr != property_ptr:
        raise ValueError("Property found at wrong place")
    return property_value[0]


def _read_int16_property(property_ptr, property_identifier):
    property_value = ffi.new('uint16_t*')
    property_found_ptr = lib.mosquitto_property_read_int16(
        property_ptr,
        property_identifier,
        property_value,
        False,
    )
    if property_found_ptr != property_ptr:
        raise ValueError("Property found at wrong place")
    return property_value[0]


def _read_int32_property(property_ptr, property_identifier):
    property_value = ffi.new('uint32_t*')
    property_found_ptr = lib.mosquitto_property_read_int32(
        property_ptr,
        property_identifier,
        property_value,
        False,
    )
    if property_found_ptr != property_ptr:
        raise ValueError("Property found at wrong place")
    return property_value[0]


def _read_varint_property(property_ptr, property_identifier):
    property_value = ffi.new('uint32_t*')
    property_found_ptr = lib.mosquitto_property_read_varint(
        property_ptr,
        property_identifier,
        property_value,
        False,
    )
    if property_found_ptr != property_ptr:
        raise ValueError("Property found at wrong place")
    return property_value[0]


def _read_binary_property(property_ptr, property_identifier):
    property_value_ptr = ffi.new('void**')
    property_value_len = ffi.new('uint16_t*')
    property_found_ptr = lib.mosquitto_property_read_binary(
        property_ptr,
        property_identifier,
        property_value_ptr,
        property_value_len,
        False,
    )
    if property_found_ptr != property_ptr:
        raise ValueError("Property found at wrong place")
    return _from_binary(property_value_ptr[0], property_value_len[0])


def _read_string_property(property_ptr, property_identifier):
    property_value = ffi.new('char*')
    property_value_ptr = ffi.new('char**', property_value)
    property_found_ptr = lib.mosquitto_property_read_string(
        property_ptr,
        property_identifier,
        property_value_ptr,
        False,
    )
    if property_found_ptr != property_ptr:
        raise ValueError("Property found at wrong place")
    return _from_cstr(property_value)


def _read_string_pair_property(property_ptr, property_identifier):
    property_name_ptr = ffi.new('char**')
    property_value_ptr = ffi.new('char**')
    property_found_ptr = lib.mosquitto_property_read_string_pair(
        property_ptr,
        property_identifier,
        property_name_ptr,
        property_value_ptr,
        False,
    )
    if property_found_ptr != property_ptr:
        raise ValueError('Property found at wrong place')
    return (
        _from_cstr(property_name_ptr[0]),
        _from_cstr(property_value_ptr[0]),
    )


def _add_byte_property(property_ptr, property_identifier, property_value):
    result = lib.mosquitto_property_add_byte(
        property_ptr,
        property_identifier,
        property_value,
    )
    if lib.MOSQ_ERR_SUCCESS != result:
        raise ValueError(f'Adding Property to list failed: {result}')


def _add_int16_property(property_ptr, property_identifier, property_value):
    result = lib.mosquitto_property_add_int16(
        property_ptr,
        property_identifier,
        property_value,
    )
    if lib.MOSQ_ERR_SUCCESS != result:
        raise ValueError(f'Adding Property to list failed: {result}')


def _add_int32_property(property_ptr, property_identifier, property_value):
    result = lib.mosquitto_property_add_int32(
        property_ptr,
        property_identifier,
        property_value,
    )
    if lib.MOSQ_ERR_SUCCESS != result:
        raise ValueError(f'Adding Property to list failed: {result}')


def _add_varint_property(property_ptr, property_identifier, property_value):
    result = lib.mosquitto_property_add_varint(
        property_ptr,
        property_identifier,
        property_value,
    )
    if lib.MOSQ_ERR_SUCCESS != result:
        raise ValueError(f'Adding Property to list failed: {result}')


def _add_binary_property(property_ptr, property_identifier, property_value):
    result = lib.mosquitto_property_add_binary(
        property_ptr,
        property_identifier,
        *_to_binary(property_value),
    )
    if lib.MOSQ_ERR_SUCCESS != result:
        raise ValueError(f'Adding Property to list failed: {result}')


def _add_string_property(property_ptr, property_identifier, property_value):
    result = lib.mosquitto_property_add_string(
        property_ptr,
        property_identifier,
        _to_cstr(property_value),
    )
    if lib.MOSQ_ERR_SUCCESS != result:
        raise ValueError(f'Adding Property to list failed: {result}')


def _add_string_pair_property(property_ptr, property_identifier,
                              property_name, property_value):
    result = lib.mosquitto_property_add_string_pair(
        property_ptr,
        property_identifier,
        _to_cstr(property_name),
        _to_cstr(property_value),
    )
    if lib.MOSQ_ERR_SUCCESS != result:
        raise ValueError(f'Adding Property to list failed: {result}')


def _properties_to_list(properties):
    property_list = []
    property_ptr = properties
    while property_ptr != ffi.NULL:
        property_identifier = lib.mosquitto_property_identifier(property_ptr)
        property_name_cstr = lib.mosquitto_property_identifier_to_string(
            property_identifier
        )
        property_identifier_iptr = ffi.new('int*')
        property_type_iptr = ffi.new('int*')
        if lib.MOSQ_ERR_SUCCESS == lib.mosquitto_string_to_property_info(
                        property_name_cstr,
                        property_identifier_iptr,
                        property_type_iptr):
            property_name = _from_cstr(property_name_cstr)
            property_type = property_type_iptr[0]
            if lib.MQTT_PROP_TYPE_BYTE == property_type:
                property_list.append(
                    (
                        property_name, _read_byte_property(
                            property_ptr,
                            property_identifier
                        )
                    )
                )
            elif lib.MQTT_PROP_TYPE_INT16 == property_type:
                property_list.append(
                    (
                        property_name,
                        _read_int16_property(
                            property_ptr,
                            property_identifier
                        )
                    )
                )
            elif lib.MQTT_PROP_TYPE_INT32 == property_type:
                property_list.append(
                    (
                        property_name,
                        _read_int32_property(
                            property_ptr,
                            property_identifier
                        )
                    )
                )
            elif lib.MQTT_PROP_TYPE_VARINT == property_type:
                property_list.append(
                    (
                        property_name,
                        _read_varint_property(
                            property_ptr,
                            property_identifier
                        )
                    )
                )
            elif lib.MQTT_PROP_TYPE_BINARY == property_type:
                property_list.append(
                    (
                        property_name,
                        _read_binary_property(
                            property_ptr,
                            property_identifier
                        )
                    )
                )
            elif lib.MQTT_PROP_TYPE_STRING == property_type:
                property_list.append(
                    (
                        property_name,
                        _read_string_property(
                            property_ptr,
                            property_identifier
                        )
                    )
                )
            elif lib.MQTT_PROP_TYPE_STRING_PAIR == property_type:
                property_list.append(
                    (
                        property_name,
                        _read_string_pair_property(
                            property_ptr,
                            property_identifier
                        )
                    )
                )
        property_ptr = lib.mosquitto_property_next(property_ptr)
    return property_list


def _list_to_properties(property_list):
    property_ptr = ffi.new('mosquitto_property**')
    for property_name, property_value in property_list:
        property_name_cstr = _to_cstr(property_name)
        property_identifier_iptr = ffi.new('int*')
        property_type_iptr = ffi.new('int*')
        if lib.MOSQ_ERR_SUCCESS == lib.mosquitto_string_to_property_info(
                        property_name_cstr,
                        property_identifier_iptr,
                        property_type_iptr):
            property_identifier = property_identifier_iptr[0]
            property_type = property_type_iptr[0]
            if lib.MQTT_PROP_TYPE_BYTE == property_type:
                _add_byte_property(
                    property_ptr,
                    property_identifier,
                    property_value
                )
            elif lib.MQTT_PROP_TYPE_INT16 == property_type:
                _add_int16_property(
                    property_ptr,
                    property_identifier,
                    property_value
                )
            elif lib.MQTT_PROP_TYPE_INT32 == property_type:
                _add_int32_property(
                    property_ptr,
                    property_identifier,
                    property_value
                )
            elif lib.MQTT_PROP_TYPE_VARINT == property_type:
                _add_varint_property(
                    property_ptr,
                    property_identifier,
                    property_value
                )
            elif lib.MQTT_PROP_TYPE_BINARY == property_type:
                _add_binary_property(
                    property_ptr,
                    property_identifier,
                    property_value
                )
            elif lib.MQTT_PROP_TYPE_STRING == property_type:
                _add_string_property(
                    property_ptr,
                    property_identifier,
                    property_value
                )
            elif lib.MQTT_PROP_TYPE_STRING_PAIR == property_type:
                _add_string_pair_property(
                    property_ptr,
                    property_identifier,
                    *property_value
                )
            else:
                raise ValueError(
                    f'Unimplemented property type {property_type}'
                )
        else:
            raise ValueError(f'Unknown property with name {property_name}')
    return property_ptr[0]


class MosquittoCallbackHandler(object):
    def __init__(self):
        self._modules = []

    def plugin_init(self, options):
        modules = [v for k, v in options.items() if k == "pyplugin_module"]
        options = {k: v for k, v in options.items() if k != "pyplugin_module"}

        for m in modules:
            module = importlib.import_module(m)
            if hasattr(module, 'plugin_init'):
                result = module.plugin_init(options)
                if result:
                    module = result
            self._modules.append(module)

        return lib.MOSQ_ERR_SUCCESS

    def plugin_cleanup(self, options):
        options = {k: v for k, v in options.items() if k != "pyplugin_module"}

        for module in self._modules:
            if hasattr(module, 'plugin_cleanup'):
                module.plugin_cleanup(options)

        _HANDLER.remove(self)

    def basic_auth(self, client, username, password):
        for module in self._modules:
            if hasattr(module, 'basic_auth'):
                result = module.basic_auth(client, username, password)
                if result != lib.MOSQ_ERR_PLUGIN_DEFER:
                    return result

        return lib.MOSQ_ERR_PLUGIN_DEFER

    def acl_check(self, client, topic, access, payload):
        for module in self._modules:
            if hasattr(module, 'acl_check'):
                result = module.acl_check(
                    client, topic, access, payload,
                )
                if result != lib.MOSQ_ERR_PLUGIN_DEFER:
                    return result

        return lib.MOSQ_ERR_PLUGIN_DEFER

    def psk_key(self, client, identity, hint):
        for module in self._modules:
            if hasattr(module, 'psk_key'):
                psk = module.psk_key(
                    client, identity, hint
                )
                if psk is not None:
                    return psk

        return None

    def disconnect(self, client, reason):
        for module in self._modules:
            if hasattr(module, 'disconnect'):
                module.disconnect(
                    client, reason
                )

        return None

    def message(self, client, event_message):
        for module in self._modules:
            if hasattr(module, 'message'):
                result = module.message(
                    client, event_message
                )
                if result != lib.MOSQ_ERR_SUCCESS:
                    return result
        return lib.MOSQ_ERR_SUCCESS

    def tick(self):
        for module in self._modules:
            if hasattr(module, 'tick'):
                module.tick()

    def reload(self):
        for module in self._modules:
            if hasattr(module, 'reload'):
                result = module.reload()
                if result != lib.MOSQ_ERR_PLUGIN_DEFER:
                    return result

        return lib.MOSQ_ERR_PLUGIN_DEFER


def _newhandler():
    handler = MosquittoCallbackHandler()
    _HANDLER.append(handler)
    return handler


def log(loglevel, message):
    lib._mosq_log(loglevel, _to_cstr(message))


def client_address(client):
    return _from_cstr(lib._mosq_client_address(client))


def client_id(client):
    return _from_cstr(lib._mosq_client_id(client))


def client_certificate(client):
    with ffi.gc(lib._mosq_client_certificate(client), lib.free) as cert_cstr:
        cert = _from_cstr(cert_cstr)
        return cert


def client_protocol(client):
    return lib._mosq_client_protocol(client)


def client_protocol_version(client):
    return lib._mosq_client_protocol_version(client)


def client_username(client):
    return _from_cstr(lib._mosq_client_username(client))


def set_username(client, username):
    return lib._mosq_set_username(client, _to_cstr(username))


def kick_client_by_clientid(client_id, with_will):
    return lib._mosq_kick_client_by_clientid(
        _to_cstr(client_id),
        with_will,
    )


def kick_client_by_username(client_username, with_will):
    return lib._mosq_kick_client_by_username(
        _to_cstr(client_username),
        with_will,
    )


def broker_publish(clientid, topic, payload, qos, retain, properties):
    payload_ptr, payloadlen = _to_binary(payload)
    return lib.mosquitto_broker_publish_copy(
        _to_cstr(clientid),
        _to_cstr(topic),
        payloadlen,
        payload_ptr,
        qos,
        retain,
        _list_to_properties(properties))


def topic_matches_sub(sub, topic):
    return lib._mosq_topic_matches_sub(_to_cstr(sub), _to_cstr(topic))


def __getattr__(name):
    if (name and
            name[0] != '_' and
            not name.startswith('mosquitto_') and
            hasattr(lib, name)):
        return getattr(lib, name)
    raise AttributeError(f"module {__name__} has no attribute {name}")

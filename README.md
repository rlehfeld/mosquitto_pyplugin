mosquitto_pyplugin
==================

Mosquitto plugin that lets you write your plugins in Python.

Compiling
=========

You need mosquitto version 1.5.1 or higher.

Make sure you have Python dev package installed (`apt-get install
python-dev` or `apt-get install python3-dev` under Debian/Ubuntu).

You must either have mosquitto header files installed globally in
`/usr/include`, etc. or clone this repository at the top of the
mosquitto source directory. Then:

    cd mosquitto_pyplugin
    make

Pass `PYTHON` variable to compile with other Python interpreter
version than default (pypy3.9):

    make PYTHON=python3

If all goes ok, there should be `mosquitto_pyplugin.so` file in the
current directory. Copy it under path accessible for mosquitto daemon,
e.g.: `/usr/local/lib/mosquitto/`.

### Troubleshooting

If you get errors while compiling the plugin about `-lmosquitto` then you have a missing link to libmosquitto.
Just check the file `/usr/lib/libmosquitto.so` or `/usr/lib/mosquitto.so.1` exists and create a symlink:

    ln -s /usr/lib/libmosquitto.so.1 /usr/lib/libmosquitto.so

And make again the plugin. This time it should work.

Running
=======

Add following line to `mosquitto.conf`:

    plugin /path/to/mosquitto_pyplugin.so

File mosquitto_pyplugin.py must be found by the used python interpreter.
You can use PYTHONPATH to adapt this accordingly.

You must also give a pointer to Python module which is going to be
loaded (make sure it's in Python path, use `PYTHONPATH` env variable
to the rescue):

    plugin_opt_pyplugin_module some_module

Python module
=============

Python module should do required initializations when it's imported
and provide following global functions:

* `plugin_init(options)`: called on plugin init, `options` is a dictionary
  with all `plugin_opt_` params from mosquitto
  configuration (except `plugin_opt_pyplugin_module`)

* `plugin_cleanup(options)`: called on plugin cleanup, `options` is a dictionary
  with all `plugin_opt_` params from mosquitto
  configuration (except `plugin_opt_pyplugin_module`)

* `basic_auth(client, username, password)`: return mosquitto_pyplugin.MOSQ_ERR_SUCCESS if given
  client, username and password combination is allowed to log in
  or mosquitto_pyplugin.MOSQ_ERR_PLUGIN_DEFER if another module should take care

* `acl_check(client, topic, access, payload)`: return
  MOSQ_ERR_SUCCESS if given user is allowed to subscribe (`access =
  mosquitto_pyplugin.MOSQ_ACL_SUBSCRIBE`), read (`access =
  mosquitto_pyplugin.MOSQ_ACL_READ`) or publish (`access =
  mosquitto_pyplugin.MOSQ_ACL_WRITE`) to given topic (see `mosquitto_pyplugin`
  module below). `payload` argument holds message payload as bytes, or
  `None` if not applicable.
  Return mosquitto_pyplugin.MOSQ_ERR_PLUGIN_DEFER in case another plugin should take care

* `psk_key(client, identity, hint)`: return `PSK` string (in hex format without heading 0x) if given
  identity and hint pair is allowed to connect else return `""` for returning MOSQ_ERR_AUTH or `None`
  for returning MOSQ_ERR_PLUGIN_DEFER to mosquitto.

* `disconnect(client, reason)` : inform about disconnection of `client` with
  reason code `reason`

* `message(client, message_event)` : inform new message event. Message is passed as dictionary
  If the callback adapts the message, the new information is passed back to mosquitto
  and the message will be adapted accordingly.


Auxiliary module
================

Plugin module can import an auxiliary module provided by mosquitto:

    import mosquitto_pyplugin

The module provides following function:

* `log(loglevel, message)`: log `message` into mosquitto's log
  file with the given `loglevel` (one of the constants below).

* `client_address(client)`: get client address from `client`
  handle

* `client_id(client)`: get client id from `client` handle

* `client_certificate(client)`: get the client certificate
  from the `client` handle

* `client_protocol(client)`: get used client protocol from
  `client` handle

* `client_protocol_version(client)`: get used client protocol
  version from `client` handle

* `client_username(client)`: get client username from `client`
  handle

* `set_username(client, username)`: change client username
  in `client` handle to `username`

* `kick_client_by_clientid(client_id, with_will)`:

* `kick_client_by_username(client_username, with_will)`:

* `topic_matches_sub(sub, topic)`: it mirrors
  `mosquitto_topic_matches_sub` from libmosquitto C library - the
  function checks whether `topic` matches given `sub` pattern (for
  example, it returns `True` if `sub` is `/foo/#` and `topic` is
  `/foo/bar`) and is mostly useful is `acl_check` function above

The following constants for `access` parameter in `acl_check` are
provided:

* `MOSQ_ACL_NONE`
* `MOSQ_ACL_SUBSCRIBE`
* `MOSQ_ACL_READ`
* `MOSQ_ACL_WRITE`

The following constants for `loglevel` parameter in `Log` are provided:

* `MOSQ_LOG_INFO`
* `MOSQ_LOG_NOTICE`
* `MOSQ_LOG_WARNING`
* `MOSQ_LOG_ERR`
* `MOSQ_LOG_DEBUG`
* `MOSQ_LOG_SUBSCRIBE` (not recommended for use by plugins)
* `MOSQ_LOG_UNSUBSCRIBE` (not recommended for use by plugins)

The following constants for `errors` are provided:

* `MOSQ_ERR_SUCCESS`
* `MOSQ_ERR_INVAL`
* `MOSQ_ERR_NOMEM`
* `MOSQ_ERR_AUTH`
* `MOSQ_ERR_UNKNOWN`
* `MOSQ_ERR_PLUGIN_DEFER`

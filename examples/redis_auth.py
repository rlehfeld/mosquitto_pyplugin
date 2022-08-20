# Example Redis authentication
#
# Run from command line to set password and acl, for example:
#
#   python redis_auth.py foo foobar '/foo/#'
#
# Syntax:
#
#   python redis_auth.py <username> <password> <allowed topic>

import hashlib
import redis
if __name__ == '__main__':
    import mosquitto_pyplugin


redis_conn = None


def plugin_init(options):
    global redis_conn
    redis_host = options.get('redis_host', '127.0.0.1')
    redis_port = options.get('redis_port', 6379)
    redis_conn = redis.StrictRedis(redis_host, redis_port)
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        f'redis initialized {redis_host}:{redis_port}'
    )


def basic_auth(client_id, username, password,
               client_address, client_protocol,
               client_protocol_version):
    import mosquitto_pyplugin
    val = redis_conn.hget(f'mosq.{username}', 'auth')
    if not val:
        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            f'AUTH: no such user: {username}')
        return mosquitto_pyplugin.MOSQ_ERR_PLUGIN_DEFER
    salt, hashed = val.split(b':')
    check = hashlib.sha1(salt + password.encode()).hexdigest().encode()
    ok = (check == hashed)
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        f'AUTH: user={username}, password matches = {ok}'
    )
    if ok:
        return mosquitto_pyplugin.MOSQ_ERR_SUCCESS
    else:
        return mosquitto_pyplugin.MOSQ_ERR_PLUGIN_DEFER


def acl_check(client_id, client_username, client_address, client_protocol,
              client_protocol_version, topic, access, payload):
    if client_username is None:
        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            'AUTH required'
        )
        return mosquitto_pyplugin.MOSQ_ERR_PLUGIN_DEFER
    pat = redis_conn.hget(f'mosq.{client_username}', 'acl')
    if not pat:
        mosquitto_pyplugin.log(
            mosquitto_pyplugin.MOSQ_LOG_INFO,
            f'ACL: no such user: {client_username}'
        )
        return mosquitto_pyplugin.MOSQ_ERR_PLUGIN_DEFER
    matches = mosquitto_pyplugin.topic_matches_sub(pat.decode(), topic)
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        f'ACL: user={client_username} topic={topic}, '
        f'matches = {matches}, payload = {payload}'
    )
    if matches:
        return mosquitto_pyplugin.MOSQ_ERR_SUCCESS
    else:
        return mosquitto_pyplugin.MOSQ_ERR_PLUGIN_DEFER


def psk_key_get(identity, hint):
    mosquitto_pyplugin.log(
        mosquitto_pyplugin.MOSQ_LOG_INFO,
        f'psk_key_get {identity} {hint}'
    )
    return '0123456789'


if __name__ == '__main__':
    import random
    import string
    import sys
    try:
        username = sys.argv[1]
        password = sys.argv[2]
        acl_topic = sys.argv[3]
    except IndexError:
        sys.exit('redis_auth <username> <password> <allowed topic>')
    salt = ''.join(c for _ in range(6)
                   for c in random.choice(string.ascii_letters))
    hashed = hashlib.sha1(salt.encode() + password.encode()).hexdigest()
    conn = redis.StrictRedis()
    print(f'HSET mosq.{username} auth {salt}:{hashed}')
    conn.hset(f'mosq.{username}', 'auth', f'{salt}:{hashed}')
    print(f'HSET mosq.{username} acl {acl_topic}')
    conn.hset(f'mosq.{username}', 'acl', acl_topic)
    print(f'{username}: password set successfully')

import routeros_api

try:
    connection = routeros_api.RouterOsApiPool('172.18.141.1', username='admin', password='your_secure_router_password', plaintext_login=True)
    api = connection.get_api()
    resource = api.get_resource('/system/resource')
    res = resource.get()
    print("SUCCESS! Connected to MikroTik:", res[0].get('board-name'), res[0].get('version'))
    connection.disconnect()
except Exception as e:
    print("Failed to connect:", e)

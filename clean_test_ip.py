import routeros_api

connection = routeros_api.RouterOsApiPool('172.18.141.1', username='admin', password='your_secure_router_password', plaintext_login=True)
api = connection.get_api()
address_list = api.get_resource('/ip/firewall/address-list')
items = address_list.get(list='Suricata-Blocked', address='1.1.1.1')
for item in items:
    address_list.remove(id=item['id'])
    print("Removed test IP 1.1.1.1")
connection.disconnect()

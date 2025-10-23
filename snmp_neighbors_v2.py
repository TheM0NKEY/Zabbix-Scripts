import requests
import json
from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
from pysnmp_sync_adapter import get_cmd_sync

# === CONFIGURATION ===
ZABBIX_URL = 'http://your-zabbix-server/api_jsonrpc.php'
ZABBIX_API_TOKEN = 'your_api_token_here'
HOSTGROUP_NAME = 'Switches'
SNMP_COMMUNITY = 'public'

SNMP_OIDS = {
    'lldp_remote_name': '1.0.8802.1.1.2.1.4.1.1.9',
    'lldp_remote_port': '1.0.8802.1.1.2.1.4.1.1.7',
    'lldp_chassis_id': '1.0.8802.1.1.2.1.4.1.1.5',
    'mac_table': '1.3.6.1.2.1.17.4.3.1.1',
    'arp_ips': '1.3.6.1.2.1.4.22.1.3',
    'arp_macs': '1.3.6.1.2.1.4.22.1.2'
}

HEADERS = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {ZABBIX_API_TOKEN}'
}

def zabbix_api(method, params):
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    }
    response = requests.post(ZABBIX_URL, json=payload, headers=HEADERS)
    data = response.json()
    if 'error' in data:
        raise Exception(f"Zabbix API error: {data['error']['message']} - {data['error']['data']}")
    if 'result' not in data:
        raise Exception(f"Unexpected Zabbix API response: {data}")
    return data['result']

def get_hosts_by_group(group_name):
    groups = zabbix_api("hostgroup.get", {
        "filter": {"name": [group_name]}
    })
    if not groups:
        raise Exception(f"Host group '{group_name}' not found.")
    group_id = groups[0]['groupid']
    return zabbix_api("host.get", {
        "groupids": group_id,
        "output": ["hostid", "host", "name"],
        "selectInterfaces": ["ip"],
        "selectInventory": ["macaddress_a", "macaddress_b"]
    })

def get_all_hosts():
    return zabbix_api("host.get", {
        "output": ["hostid", "host", "name"],
        "selectInterfaces": ["ip"],
        "selectInventory": ["macaddress_a", "macaddress_b"]
    })

def update_macro(hostid, macro_name, macro_value):
    macros = zabbix_api("usermacro.get", {
        "hostids": hostid,
        "filter": {"macro": macro_name}
    })
    if macros:
        macro_id = macros[0]['hostmacroid']
        zabbix_api("usermacro.update", {
            "hostmacroid": macro_id,
            "value": macro_value
        })
    else:
        zabbix_api("usermacro.create", {
            "hostid": hostid,
            "macro": macro_name,
            "value": macro_value
        })

def update_tags(hostid, tags):
    zabbix_api("host.update", {
        "hostid": hostid,
        "tags": tags
    })

# === SNMP POLLING ===
def snmp_get(ip, oid):
    try:
        result = get_cmd_sync(
            SnmpEngine(),
            CommunityData(SNMP_COMMUNITY),
            UdpTransportTarget((ip, 161), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        return [str(varBind[1]) for varBind in result[3]]
    except Exception:
        return []

def snmp_get_all(ip):
    data = {}
    for key, oid in SNMP_OIDS.items():
        data[key] = snmp_get(ip, oid)
    return data

# === MATCHING LOGIC ===
def build_lookup_table(all_hosts):
    lookup = {}
    for host in all_hosts:
        name = host.get('name')
        ip = None
        macs = []

        if isinstance(host.get('interfaces'), list) and host['interfaces']:
            ip = host['interfaces'][0].get('ip')

        inventory = host.get('inventory', {})
        if isinstance(inventory, dict):
            macs = [inventory.get('macaddress_a'), inventory.get('macaddress_b')]

        for key in [name, ip] + macs:
            if key and key not in lookup:
                lookup[key] = host
    return lookup

def match_snmp_to_hosts(snmp_data, lookup):
    matched = set()
    for key in ['lldp_remote_name', 'lldp_chassis_id', 'arp_ips', 'arp_macs']:
        for value in snmp_data.get(key, []):
            if value in lookup:
                matched.add(lookup[value]['name'])
    return list(matched)

# === MAIN LOGIC ===
def main():
    try:
        target_hosts = get_hosts_by_group(HOSTGROUP_NAME)
        all_hosts = get_all_hosts()
        lookup = build_lookup_table(all_hosts)
    except Exception as e:
        print(f"[ERROR] {e}")
        return

    for host in target_hosts:
        ip = None
        if isinstance(host.get('interfaces'), list) and host['interfaces']:
            ip = host['interfaces'][0].get('ip')

        if not ip:
            print(f"[SKIP] No IP found for {host['host']}")
            continue

        print(f"[INFO] Polling {host['host']} ({ip})...")
        try:
            snmp_data = snmp_get_all(ip)
            macro_raw = json.dumps(snmp_data)
            update_macro(host['hostid'], '{$NEIGHBOURS}', macro_raw)

            matched_hosts = match_snmp_to_hosts(snmp_data, lookup)
            update_macro(host['hostid'], '{$NEIGHBOUR_HOSTS}', ','.join(matched_hosts))

            tags = [{"tag": "linked_to", "value": name} for name in matched_hosts]
            update_tags(host['hostid'], tags)

            print(f"[OK] Updated {host['host']} with {len(matched_hosts)} matched links.")
        except Exception as e:
            print(f"[FAIL] {host['host']} - {e}")

if __name__ == "__main__":
    main()

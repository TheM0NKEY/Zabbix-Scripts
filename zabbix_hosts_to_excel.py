#!/usr/bin/env python3
"""
zabbix_hosts_to_excel.py

Export Zabbix host data to a nicely formatted Excel workbook.

Features
- Login with API token (recommended) or username/password
- Pulls hosts with groups, templates, interfaces, tags, macros, and inventory
- Writes multiple sheets (Hosts, Interfaces, Groups, Templates, Tags, Macros, Inventory)
- Auto-sizes columns and freezes headers to keep things readable

Usage examples
--------------
# Using an API token (best practice)
python zabbix_hosts_to_excel.py --url https://zabbix.example.com/api_jsonrpc.php --token <API_TOKEN> -o hosts.xlsx

# Using username + password
python zabbix_hosts_to_excel.py --url https://zabbix.example.com/api_jsonrpc.php -u Admin -p zabbix -o hosts.xlsx
"""
import argparse
import sys
import json
import requests
import pandas as pd
from typing import Dict, Any, List, Optional
from datetime import datetime

# ---- JSON-RPC thin client ----
class ZabbixAPI:
    def __init__(self, url: str, token: Optional[str] = None, timeout: int = 30, verify_tls: bool = True):
        if not url.endswith("api_jsonrpc.php"):
            if url.endswith("/"):
                url = url + "api_jsonrpc.php"
            else:
                url = url + "/api_jsonrpc.php"
        self.url = url
        self.session = requests.Session()
        self.session.verify = verify_tls
        self.timeout = timeout
        self._token = token
        self._id = 0

    def login(self, user: str, password: str) -> str:
        result = self._rpc("user.login", {"user": user, "password": password}, use_auth=False)
        self._token = result
        return result

    def set_token(self, token: str):
        self._token = token

    def _rpc(self, method: str, params: Dict[str, Any], use_auth: bool = True) -> Any:
        self._id += 1
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self._id,
        }
        if use_auth:
            if not self._token:
                raise RuntimeError("No auth token set. Call login() or provide --token.")
            payload["auth"] = self._token
        resp = self.session.post(self.url, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise RuntimeError(f"Zabbix API error on {method}: {data['error']}")
        return data.get("result")

    # Convenience API calls
    def get_hosts(self, include_inventory: bool = True) -> List[Dict[str, Any]]:
        params = {
            "output": "extend",
            "selectGroups": ["groupid", "name"],
            "selectParentTemplates": ["templateid", "name"],
            "selectInterfaces": "extend",
            "selectMacros": "extend",
            "selectTags": "extend",
            "selectInventory": "extend" if include_inventory else None,
            "selectProxy": "extend",
        }
        # remove None items
        params = {k: v for k, v in params.items() if v is not None}
        return self._rpc("host.get", params)

# ---- Data shaping helpers ----
def list_to_comma(items: List[Dict[str, Any]], key: str) -> str:
    return ", ".join([str(x.get(key, "")) for x in items]) if items else ""

def interfaces_to_str(ifs: List[Dict[str, Any]]) -> str:
    if not ifs:
        return ""
    parts = []
    typemap = {"1": "Agent", "2": "SNMP", "3": "IPMI", "4": "JMX", 1:"Agent",2:"SNMP",3:"IPMI",4:"JMX"}
    for it in ifs:
        t = typemap.get(it.get("type"), it.get("type"))
        ip = it.get("ip") or ""
        dns = it.get("dns") or ""
        port = it.get("port") or ""
        useip = it.get("useip")
        addr = ip if str(useip) == "1" else (dns or ip)
        parts.append(f"{t}:{addr}:{port}")
    return ", ".join(parts)

def safe_get(d: Dict[str, Any], *path, default=""):
    cur = d
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur if cur is not None else default

def flatten_hosts(hosts: List[Dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for h in hosts:
        rows.append({
            "hostid": h.get("hostid"),
            "host": h.get("host"),
            "name": h.get("name") or h.get("host"),
            "status": "Enabled" if str(h.get("status")) == "0" else "Disabled",
            "available": {
                "0": "Unknown",
                "1": "Available",
                "2": "Unavailable"
            }.get(str(h.get("available", "0")), "Unknown"),
            "proxy": safe_get(h, "proxy", "host", default=""),
            "groups": list_to_comma(h.get("groups", []), "name"),
            "templates": list_to_comma(h.get("parentTemplates", []), "name"),
            "interfaces": interfaces_to_str(h.get("interfaces", [])),
            "tags": list_to_comma(h.get("tags", []), "tag"),
            "description": h.get("description", ""),
            # A few common inventory fields if present
            "inventory_type": safe_get(h, "inventory", "type"),
            "inventory_type_full": safe_get(h, "inventory", "type_full"),
            "inventory_os": safe_get(h, "inventory", "os"),
            "inventory_serialno": safe_get(h, "inventory", "serialno_a"),
            "inventory_location": safe_get(h, "inventory", "location"),
        })
    df = pd.DataFrame(rows)
    # Sort by name for readability
    if not df.empty and "name" in df.columns:
        df = df.sort_values(by=["name"]).reset_index(drop=True)
    return df

def expand_sheet(hosts: List[Dict[str, Any]], key: str, columns: List[str], extra_cols: Optional[Dict[str,str]]=None) -> pd.DataFrame:
    # Creates a normalized sheet for one-to-many relations (groups, templates, interfaces, tags, macros)
    extra_cols = extra_cols or {}
    rows = []
    for h in hosts:
        many = h.get(key, [])
        if not isinstance(many, list):
            continue
        for item in many:
            row = {"hostid": h.get("hostid"), "host": h.get("host"), "name": h.get("name") or h.get("host")}
            for c in columns:
                row[c] = item.get(c, "")
            for k, v in extra_cols.items():
                row[k] = item.get(v, "")
            rows.append(row)
    return pd.DataFrame(rows)

def expand_inventory(hosts: List[Dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for h in hosts:
        inv = h.get("inventory") or {}
        base = {"hostid": h.get("hostid"), "host": h.get("host"), "name": h.get("name") or h.get("host")}
        row = {**base, **inv}
        rows.append(row)
    return pd.DataFrame(rows)

def auto_size_and_freeze(writer: pd.ExcelWriter, sheet_name: str, df: pd.DataFrame):
    try:
        ws = writer.sheets[sheet_name]
        # Auto-size columns
        for idx, col in enumerate(df.columns, 1):
            maxlen = max([len(str(col))] + [len(str(x)) for x in df[col].astype(str).tolist()]) if not df.empty else len(str(col))
            ws.column_dimensions[chr(64 + idx) if idx <= 26 else 'A'].width = min(maxlen + 2, 80)
        # Freeze header row
        ws.freeze_panes = "A2"
        # Apply autofilter
        if not df.empty:
            ws.auto_filter.ref = f"A1:{chr(64+len(df.columns)) if len(df.columns)<=26 else 'Z'}{len(df)+1}"
    except Exception:
        pass  # best-effort formatting

def main():
    parser = argparse.ArgumentParser(description="Export Zabbix host data to an Excel workbook.")
    parser.add_argument("--url", required=True, help="Zabbix base URL or full API endpoint (will append /api_jsonrpc.php if needed)")
    auth = parser.add_mutually_exclusive_group(required=True)
    auth.add_argument("--token", help="Zabbix API token (recommended)")
    auth.add_argument("-u", "--user", help="Username for Zabbix (if no token)")
    parser.add_argument("-p", "--password", help="Password for Zabbix user")
    parser.add_argument("-o", "--output", default=f"zabbix_hosts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                        help="Output Excel filename (default includes timestamp)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds (default 30)")
    args = parser.parse_args()

    if args.user and not args.password:
        print("ERROR: --password is required when using --user", file=sys.stderr)
        sys.exit(2)

    api = ZabbixAPI(args.url, timeout=args.timeout, verify_tls=not args.insecure)
    try:
        if args.token:
            api.set_token(args.token)
        else:
            api.login(args.user, args.password)
    except Exception as e:
        print(f"Authentication failed: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        hosts = api.get_hosts(include_inventory=True)
    except Exception as e:
        print(f"Failed to fetch hosts: {e}", file=sys.stderr)
        sys.exit(1)

    # Build DataFrames
    df_hosts = flatten_hosts(hosts)
    df_groups = expand_sheet(hosts, "groups", ["groupid", "name"])
    df_templates = expand_sheet(hosts, "parentTemplates", ["templateid", "name"])
    df_interfaces = expand_sheet(hosts, "interfaces", ["interfaceid", "type", "ip", "dns", "port", "useip"])
    df_tags = expand_sheet(hosts, "tags", ["tag", "value"])
    df_macros = expand_sheet(hosts, "macros", ["macro", "value"])
    df_inventory = expand_inventory(hosts)

    # Write Excel with formatting
    try:
        with pd.ExcelWriter(args.output, engine="openpyxl") as writer:
            sheets = [
                ("Hosts", df_hosts),
                ("Interfaces", df_interfaces),
                ("Groups", df_groups),
                ("Templates", df_templates),
                ("Tags", df_tags),
                ("Macros", df_macros),
                ("Inventory", df_inventory),
            ]
            for name, df in sheets:
                df.to_excel(writer, index=False, sheet_name=name)
                auto_size_and_freeze(writer, name, df)
        print(f"✅ Exported {len(df_hosts)} hosts to '{args.output}'")
    except Exception as e:
        print(f"Failed to write Excel: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

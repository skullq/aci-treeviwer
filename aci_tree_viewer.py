import requests
import json
import urllib3
import re
import argparse
import configparser
import time

from collections import defaultdict
from datetime import datetime
from rich.console import Console
from rich.tree import Tree
from rich.text import Text
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Tree as TextualTree, Static, Button, Label, Tabs, Tab, Input, ListView, ListItem, DataTable
from textual.containers import Container, ScrollableContainer, Vertical
from textual.events import Key
from rich.panel import Panel
from textual.screen import ModalScreen
from textual.message import Message

# SSL 인증서 경고 무시
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AciTreeViewer:
    def __init__(self, url, user, password):
        self.url = url
        self.session = requests.Session()
        self.login(user, password)

    def login(self, user, password):
        login_url = f"{self.url}/api/aaaLogin.json"
        payload = {"aaaUser": {"attributes": {"name": user, "pwd": password}}}
        try:
            response = self.session.post(login_url, json=payload, verify=False, timeout=10)
            if not response.ok: raise Exception("Login Failed")
            print(f"[*] Connected to {self.url}")
        except Exception as e:
            print(f"[!] Connection Error: {e}")
            exit()

    def get_data(self, class_name):
        query_url = f"{self.url}/api/node/class/{class_name}.json"
        try:
            response = self.session.get(query_url, verify=False, timeout=15)
            return response.json().get('imdata', [])
        except: return []

    def _format_tag(self, tag):
        """pcTag 포맷팅 (0 또는 특정 예약어는 vzAny로 표시)"""
        return "vzAny" if str(tag) in ['0', 'any', 'unspecified'] else tag

    def _format_scope(self, scope):
        """L3Out Subnet Scope 포맷팅"""
        if not scope: return "N/A"
        scope_map = {
            'import-security': 'External EPG',
            'import-rtctrl': 'Import Route Control',
            'export-rtctrl': 'Export Route Control',
            'shared-rtctrl': 'Shared Route Control',
            'shared-security': 'Shared Security',
        }
        return ", ".join([scope_map.get(s.strip(), s.strip()) for s in scope.split(',') if s.strip()])

    def _format_health_status(self, dn, health_map, fault_map):
        """Formats health score and fault count into a rich text string."""
        parts = []
        health = health_map.get(dn)
        faults = fault_map.get(dn, 0)

        if health is not None:
            try:
                health_val = int(health)
                color = "green" if health_val >= 90 else "yellow" if health_val >= 70 else "red"
                parts.append(f"[{color}]Health Check: {health_val}[/{color}]")
            except ValueError:
                parts.append(f"[dim]Health Check: {health}[/dim]")
        else:
            parts.append("[dim]Health Check: N/A[/dim]")

        if faults > 0:
            parts.append(f"[bold red]Faults: {faults}[/bold red]")
        else:
            parts.append("[green]Faults: 0[/green]")
            
        return f" ({', '.join(parts)})"

    def _fetch_all_data(self, specific_classes=None):
        """모든 ACI 객체 데이터 수집"""
        all_classes = [
            'fvTenant', 'fvCtx', 'fvBD', 'fvAEPg', 'fvSubnet',
            'l3extOut', 'l3extInstP', 'l3extSubnet',
            'fvRsProv', 'fvRsCons', 'l3extRsProv', 'l3extRsCons',
            'vnsRsAbsGraphAtt', 'fvRsCtx', 'fvRsBd', 'l3extRsEctx',
            'vzAny', 'vzRsAnyToProv', 'vzRsAnyToCons', 'vzSubj', 'vzBrCP', 'ipRouteP', 'fabricNode', 'fabricVpcRT', 'fvRsPathAtt',
            'ipNexthopP', 'healthInst', 'faultInst', 'l3extRsPathL3OutAtt', 'lldpAdjEp', 'vnsRsCIfPathAtt', 'l1PhysIf', 'fabricNodePEp'
        ]
        classes_to_fetch = specific_classes if specific_classes else all_classes
        return {cls: self.get_data(cls) for cls in classes_to_fetch}

    def _process_mappings(self, data):
        """데이터 관계 매핑 생성"""
        # 1. VRF 매핑
        bd_to_vrf = {r['fvRsCtx']['attributes']['dn'].replace('/rsctx', ''): r['fvRsCtx']['attributes']['tnFvCtxName'] 
                     for r in data['fvRsCtx'] if 'fvRsCtx' in r}
        l3_to_vrf = {r['l3extRsEctx']['attributes']['dn'].replace('/rsectx', ''): r['l3extRsEctx']['attributes']['tnFvCtxName'] 
                     for r in data['l3extRsEctx'] if 'l3extRsEctx' in r}

        # 2. Service Graph 매핑
        cont_to_graph = {}
        for gi in data['vnsRsAbsGraphAtt']:
            attr = gi.get('vnsRsAbsGraphAtt', {}).get('attributes', {})
            if attr:
                c_match = re.search(r'brc-([^/]+)', attr['dn'])
                if c_match: cont_to_graph[c_match.group(1)] = attr.get('tnVnsAbsGraphName', 'Unknown')

        # 3. Contract 매핑
        total_conts = defaultdict(lambda: {"prov": [], "cons": []})
        def safe_map(source, key, type_key):
            for item in source:
                if key in item:
                    attr = item[key]['attributes']
                    dn_parent = attr['dn'].split('/rs')[0]
                    c_name = attr.get('tnVzBrCPName')
                    total_conts[dn_parent][type_key].append(c_name)

        safe_map(data['fvRsProv'], 'fvRsProv', 'prov')
        safe_map(data['fvRsCons'], 'fvRsCons', 'cons')
        safe_map(data['l3extRsProv'], 'l3extRsProv', 'prov')
        safe_map(data['l3extRsCons'], 'l3extRsCons', 'cons')
        safe_map(data['vzRsAnyToProv'], 'vzRsAnyToProv', 'prov')
        safe_map(data['vzRsAnyToCons'], 'vzRsAnyToCons', 'cons')

        # Map: (Tenant, ContractName) -> Scope
        contract_scopes = {}
        for c in data.get('vzBrCP', []):
            if 'vzBrCP' in c:
                attr = c['vzBrCP']['attributes']
                dn = attr['dn']
                match = re.match(r'uni/tn-([^/]+)/brc-([^/]+)', dn)
                if match:
                    contract_scopes[(match.group(1), match.group(2))] = attr.get('scope', 'unknown')
        
        contract_name_to_tenants = defaultdict(set)
        for (t, c) in contract_scopes.keys():
            contract_name_to_tenants[c].add(t)

        # 4. Subnet 및 광고 정보
        vrf_public_subnets = defaultdict(list)
        bd_subnets = defaultdict(list)
        for s in data.get('fvSubnet', []):
            if 'fvSubnet' in s:
                attr = s['fvSubnet']['attributes']
                bd_dn = attr['dn'].split('/subnet-')[0]
                bd_subnets[bd_dn].append(attr['ip'])

        for s in data.get('fvSubnet', []):
            if 'fvSubnet' in s:
                attr = s['fvSubnet']['attributes']
                if 'public' in attr.get('scope', ''):
                    bd_dn = attr['dn'].split('/subnet-')[0]
                    v_name = bd_to_vrf.get(bd_dn)
                    if v_name: vrf_public_subnets[v_name].append(attr['ip'])

        l3out_ext_info = defaultdict(list)
        for ls in data.get('l3extSubnet', []):
            if 'l3extSubnet' in ls:
                attr = ls['l3extSubnet']['attributes']
                ip, pctag = attr.get('ip', ''), attr.get('pcTag')
                if not pctag or pctag in ['0', 'unspecified']: pctag = '15' if ip == '0.0.0.0/0' else 'N/A'
                match = re.match(r'(uni/tn-[^/]+/out-[^/]+)', attr['dn'])
                if match and (ip == '0.0.0.0/0' or pctag == '15'):
                    l3out_ext_info[match.group(1)].append(f"0.0.0.0/0 (pcTag:{self._format_tag(pctag)})")

        # 5. Contract Direction (vzSubj)
        contract_info = {}
        for subj in data.get('vzSubj', []):
            if 'vzSubj' in subj:
                attr = subj['vzSubj']['attributes']
                dn = attr['dn']
                # dn: uni/tn-{t}/brc-{c}/subj-{s}
                match = re.search(r'uni/tn-([^/]+)/brc-([^/]+)', dn)
                if match:
                    key = (match.group(1), match.group(2))
                    direction = "Bi" if attr.get('revFltPorts', 'yes') == 'yes' else "Uni"
                    # If any subject is Bi, treat contract as Bi
                    if key not in contract_info or direction == "Bi":
                        contract_info[key] = direction

        # 6. L3Out InstP Subnets
        instp_subnets = defaultdict(list)
        for sub in data.get('l3extSubnet', []):
            if 'l3extSubnet' in sub:
                attr = sub['l3extSubnet']['attributes']
                match = re.match(r'(.+/instP-[^/]+)/extsubnet-.+', attr['dn'])
                if match:
                    instp_subnets[match.group(1)].append(attr)

        # 7. Static Routes Mapping
        l3out_static_routes = defaultdict(list)
        route_dn_map = {}
        
        for r in data.get('ipRouteP', []):
            if 'ipRouteP' in r:
                attr = r['ipRouteP']['attributes']
                dn = attr['dn']
                l3_match = re.match(r'(uni/tn-[^/]+/out-[^/]+)', dn)
                node_match = re.search(r'node-(\d+)', dn)
                
                if l3_match:
                    l3_dn = l3_match.group(1)
                    route_obj = {'prefix': attr.get('ip', '0.0.0.0/0'), 'node': node_match.group(1) if node_match else "All", 'nexthops': [], 'dn': dn}
                    l3out_static_routes[l3_dn].append(route_obj)
                    route_dn_map[dn] = route_obj

        for nh in data.get('ipNexthopP', []):
            if 'ipNexthopP' in nh:
                attr = nh['ipNexthopP']['attributes']
                p_dn = attr['dn'].rsplit('/', 1)[0]
                if p_dn in route_dn_map:
                    route_dn_map[p_dn]['nexthops'].append(attr.get('nhAddr', ''))

        # 8. Health and Fault Mapping
        health_map = {}
        for h in data.get('healthInst', []):
            if 'healthInst' in h:
                dn = h['healthInst']['attributes']['dn']
                parent_dn = dn.rsplit('/', 1)[0]
                health_map[parent_dn] = h['healthInst']['attributes']['cur']

        fault_map = defaultdict(int)
        for f in data.get('faultInst', []):
            if 'faultInst' in f:
                parent_dn = f['faultInst']['attributes']['dn'].rsplit('/fault-', 1)[0]
                fault_map[parent_dn] += 1
        
        # 9. DN to Full Object and App-Centric Mapping
        dn_to_full_obj = {}
        for class_name, objects in data.items():
            if class_name in ['imdata', 'healthInst', 'faultInst']: continue
            for obj_wrapper in objects:
                if class_name in obj_wrapper:
                    attrs = obj_wrapper[class_name].get('attributes', {})
                    if 'dn' in attrs:
                        dn_to_full_obj[attrs['dn']] = attrs
        
        dn_to_name = {t['fvTenant']['attributes']['dn']: t['fvTenant']['attributes']['name'] for t in data.get('fvTenant', []) if 'fvTenant' in t}
        for epg in data.get('fvAEPg', []):
            if 'fvAEPg' in epg:
                dn = epg['fvAEPg']['attributes']['dn']
                name = epg['fvAEPg']['attributes']['name']
                tenant_match = re.search(r'tn-([^/]+)', dn)
                ap_match = re.search(r'ap-([^/]+)', dn)
                if tenant_match and ap_match:
                    dn_to_name[dn] = f"{tenant_match.group(1)}/{ap_match.group(1)}/{name}"
                else:
                    dn_to_name[dn] = name

        # 10. vPC Pairs
        vpc_pairs = {}
        processed_vpc_nodes = set()
        
        # Method 1: fabricNodePEp (Explicit Configuration)
        vpc_groups = defaultdict(list)
        for np in data.get('fabricNodePEp', []):
            if 'fabricNodePEp' in np:
                attr = np['fabricNodePEp']['attributes']
                parent_dn = attr['dn'].rsplit('/', 1)[0]
                vpc_groups[parent_dn].append(attr['id'])
        
        for nodes in vpc_groups.values():
            if len(nodes) == 2:
                n1, n2 = sorted(nodes)
                vpc_pairs[n1] = n2
                vpc_pairs[n2] = n1
                processed_vpc_nodes.add(n1)
                processed_vpc_nodes.add(n2)

        for rt in data.get('fabricVpcRT', []):
            if 'fabricVpcRT' in rt:
                dn = rt['fabricVpcRT']['attributes']['dn']
                match = re.search(r'rt-vpcp-.+-(\d+)-(\d+)', dn)
                if match:
                    node1, node2 = sorted([match.group(1), match.group(2)])
                    if node1 not in processed_vpc_nodes and node2 not in processed_vpc_nodes:
                        vpc_pairs[node1] = node2
                        vpc_pairs[node2] = node1
                        processed_vpc_nodes.add(node1)
                        processed_vpc_nodes.add(node2)

        # 11. Port Attributes (l1PhysIf)
        port_attributes = {}
        for phys in data.get('l1PhysIf', []):
            if 'l1PhysIf' in phys:
                attr = phys['l1PhysIf']['attributes']
                dn = attr['dn']
                # topology/pod-1/node-101/sys/phys-[eth1/33]
                match = re.search(r'node-(\d+)/sys/phys-\[(.+?)\]', dn)
                if match:
                    node_id, port_name = match.groups()
                    port_attributes[(node_id, port_name)] = attr

        # 12. Port Mappings
        port_details_map = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

        def parse_path_dn(t_dn):
            """Parses tDn to extract node(s) and interface."""
            # Single Node: topology/pod-1/paths-101/pathep-[eth1/1]
            s_match = re.search(r'paths-(\d+)/pathep-\[(.+?)\]', t_dn)
            if s_match:
                return [(s_match.group(1), s_match.group(2))]
            
            # vPC: topology/pod-1/protpaths-101-102/pathep-[eth1/1]
            v_match = re.search(r'protpaths-(\d+)-(\d+)/pathep-\[(.+?)\]', t_dn)
            if v_match:
                return [(v_match.group(1), v_match.group(3)), (v_match.group(2), v_match.group(3))]
            return []

        # EPGs
        for path in data.get('fvRsPathAtt', []):
            if 'fvRsPathAtt' in path:
                attr = path['fvRsPathAtt']['attributes']
                epg_dn = attr['dn'].split('/rspathAtt-')[0]
                path_dn = attr['tDn']
                vlan = attr.get('encap', 'untagged').replace('vlan-', '')
                
                for node_id, if_name in parse_path_dn(path_dn):
                    epg_name = dn_to_name.get(epg_dn, epg_dn)
                    port_details_map[node_id][if_name][vlan].append({'type': 'EPG', 'name': epg_name})

        # L3Outs
        for path in data.get('l3extRsPathL3OutAtt', []):
            if 'l3extRsPathL3OutAtt' in path:
                attr = path['l3extRsPathL3OutAtt']['attributes']
                dn = attr['dn']
                path_dn = attr['tDn']
                vlan = attr.get('encap', 'untagged').replace('vlan-', '')
                # Extract L3Out Name: uni/tn-X/out-Y/...
                l3_match = re.search(r'out-([^/]+)', dn)
                l3_name = l3_match.group(1) if l3_match else "Unknown L3Out"
                
                for node_id, if_name in parse_path_dn(path_dn):
                    port_details_map[node_id][if_name][vlan].append({'type': 'L3Out', 'name': l3_name})

        # Service Graphs (L4-L7)
        for path in data.get('vnsRsCIfPathAtt', []):
            if 'vnsRsCIfPathAtt' in path:
                attr = path['vnsRsCIfPathAtt']['attributes']
                dn = attr['dn']
                path_dn = attr['tDn']
                # Extract Device Name: uni/tn-X/lDevVip-Dev/cDev-Node/cIf-Int/...
                dev_match = re.search(r'lDevVip-([^/]+)', dn)
                dev_name = dev_match.group(1) if dev_match else "Unknown Device"
                
                for node_id, if_name in parse_path_dn(path_dn):
                    port_details_map[node_id][if_name]['untagged'].append({'type': 'Service', 'name': dev_name})

        # LLDP Neighbors (Switch Links)
        for adj in data.get('lldpAdjEp', []):
            if 'lldpAdjEp' in adj:
                attr = adj['lldpAdjEp']['attributes']
                dn = attr['dn']
                # topology/pod-1/node-101/sys/lldp/inst/if-[eth1/49]/adj-1
                node_match = re.search(r'node-(\d+)', dn)
                if_match = re.search(r'if-\[(.+?)\]', dn)
                
                if node_match and if_match:
                    node_id = node_match.group(1)
                    if_name = if_match.group(1)
                    sys_name = attr.get('sysName', 'Unknown')
                    port_desc = attr.get('portDesc', '')
                    port_details_map[node_id][if_name]['-neighbor'].append({'type': 'Neighbor', 'name': sys_name, 'remote': port_desc})
        
        # 13. Port View Search Helpers
        epg_to_ports = defaultdict(list)
        fabric_ports = defaultdict(list) # node_id -> list of (port, neighbor_name, remote_port)
        service_ports = defaultdict(list) # node_id -> list of (port, device_name)
        
        fabric_node_names = {n['fabricNode']['attributes']['name'] for n in data.get('fabricNode', []) if 'fabricNode' in n}

        for node_id, ports in port_details_map.items():
            for port, vlans in ports.items():
                for vlan, items in vlans.items():
                    for item in items:
                        if item['type'] == 'EPG':
                            epg_to_ports[item['name']].append((node_id, port, vlan))
                        elif item['type'] == 'Service':
                            service_ports[node_id].append((port, item['name']))
                        elif item['type'] == 'Neighbor':
                            if item['name'] in fabric_node_names or 'apic' in item['name'].lower():
                                fabric_ports[node_id].append((port, item['name'], item.get('remote', '')))

        app_centric_map = defaultdict(lambda: {'prov': set(), 'cons': set()})
        contract_providers = defaultdict(set)
        contract_consumers = defaultdict(set)
        dn_to_name = {t['fvTenant']['attributes']['dn']: t['fvTenant']['attributes']['name'] for t in data.get('fvTenant', []) if 'fvTenant' in t}
        
        epg_to_bd = {}
        for rs in data.get('fvRsBd', []):
            if 'fvRsBd' in rs:
                attr = rs['fvRsBd']['attributes']
                epg_dn = attr['dn'].replace('/rsbd', '')
                epg_to_bd[epg_dn] = attr['tDn']

        vrf_to_epgs = defaultdict(list)
        for epg_dn, bd_dn in epg_to_bd.items():
            vrf_name = bd_to_vrf.get(bd_dn)
            if vrf_name:
                match = re.match(r'uni/tn-([^/]+)', epg_dn)
                if match:
                    tenant = match.group(1)
                    epg_name = dn_to_name.get(epg_dn, epg_dn.split('/')[-1])
                    vrf_to_epgs[(tenant, vrf_name)].append((epg_name, epg_dn))

        for epg in data.get('fvAEPg', []):
            if 'fvAEPg' in epg:
                dn_to_name[epg['fvAEPg']['attributes']['dn']] = epg['fvAEPg']['attributes']['name']
        for epg in data.get('l3extInstP', []):
            if 'l3extInstP' in epg:
                dn_to_name[epg['l3extInstP']['attributes']['dn']] = epg['l3extInstP']['attributes']['name']
        for dn, conts in total_conts.items():
            if not ('/epg-' in dn or '/instP-' in dn or dn.endswith('/any')): continue
            tenant_match = re.match(r'uni/tn-([^/]+)', dn)
            if not tenant_match: continue
            tenant_name = tenant_match.group(1)
            
            if dn.endswith('/any'):
                vrf_match = re.search(r'/ctx-([^/]+)/', dn)
                vrf_name = vrf_match.group(1) if vrf_match else "Unknown"
                epg_name = f"vzAny ({vrf_name})"
            else:
                epg_name = dn_to_name.get(dn, dn.split('/')[-1])

            for contract_name in conts['prov']:
                c_owner = tenant_name
                if (tenant_name, contract_name) not in contract_scopes:
                    if ('common', contract_name) in contract_scopes:
                        c_owner = 'common'
                    else:
                        owners = contract_name_to_tenants.get(contract_name)
                        if owners:
                            c_owner = list(owners)[0]

                app_centric_map[(tenant_name, contract_name)]['prov'].add((epg_name, dn))
                contract_providers[(c_owner, contract_name)].add((tenant_name, epg_name, dn))
            for contract_name in conts['cons']:
                c_owner = tenant_name
                if (tenant_name, contract_name) not in contract_scopes:
                    if ('common', contract_name) in contract_scopes:
                        c_owner = 'common'
                    else:
                        owners = contract_name_to_tenants.get(contract_name)
                        if owners:
                            c_owner = list(owners)[0]

                app_centric_map[(tenant_name, contract_name)]['cons'].add((epg_name, dn))
                contract_consumers[(c_owner, contract_name)].add((tenant_name, epg_name, dn))

        return {
            'bd_to_vrf': bd_to_vrf,
            'l3_to_vrf': l3_to_vrf,
            'cont_to_graph': cont_to_graph,
            'total_conts': total_conts,
            'vrf_public_subnets': vrf_public_subnets,
            'l3out_ext_info': l3out_ext_info,
            'contract_info': contract_info,
            'instp_subnets': instp_subnets, 'l3out_static_routes': l3out_static_routes, 'bd_subnets': bd_subnets, 'epg_to_bd': epg_to_bd,
            'health_map': health_map, 'fault_map': fault_map, 'app_centric_map': app_centric_map,
            'dn_to_full_obj': dn_to_full_obj, 'contract_providers': contract_providers,
            'contract_scopes': contract_scopes, 'vpc_pairs': vpc_pairs,
            'port_details_map': port_details_map, 'contract_consumers': contract_consumers, 
            'vrf_to_epgs': vrf_to_epgs, 'epg_to_ports': epg_to_ports,
            'fabric_ports': fabric_ports, 'service_ports': service_ports,
            'contract_name_to_tenants': contract_name_to_tenants,
            'port_attributes': port_attributes
        }

    def visualize_tree(self):
        app = AciTreeViewerApp(self)
        app.run()

# --- Custom Messages for Worker Communication ---
class StatusUpdate(Message):
    """A message to update the loading status."""
    def __init__(self, message: str, color: str = "yellow") -> None:
        self.message = message
        self.color = color
        super().__init__()

class LoadingComplete(Message):
    """A message to indicate that loading is complete."""
    pass
# ----------------------------------------------

class WelcomeScreen(ModalScreen):
    """Screen with a welcome message."""

    def __init__(self, is_help_view: bool = False, **kwargs):
        self.is_help_view = is_help_view
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        common_widgets = [
            Label("Welcome to ACI Tree Viewer", classes="welcome-header"),
            Label(" ", classes="welcome-text"),
            Label("Use [bold]Tab[/bold] to switch focus between Tabs and Tree.", classes="welcome-text"),
            Label("When Tabs are focused, use [bold]Left/Right[/bold] to switch views.", classes="welcome-text"),
            Label(" ", classes="welcome-text"),
            Label("[u]Key Bindings:[/u]", classes="welcome-text"),
            Label("  [bold]r[/bold]          Refresh Data", classes="welcome-text"),
            Label("  [bold]q[/bold]          Quit", classes="welcome-text"),
            Label("  [bold]Up/Down[/bold]    Navigate Tree Nodes", classes="welcome-text"),
            Label("  [bold]Left/Right[/bold] Collapse/Expand Node", classes="welcome-text"),
            Label("  [bold]Space[/bold]       Toggle Node Expansion", classes="welcome-text"),
            Label("  [bold]s[/bold]           Search (Node Port View only)", classes="welcome-text"),
            Label("  [bold]w[/bold]           Save Report to File", classes="welcome-text"),
            Label(" ", classes="welcome-text"),
        ]
        if self.is_help_view:
            action_widgets = [Button("Close", variant="primary", id="start")]
        else:
            action_widgets = [
                Label("Initializing...", id="loading_status", classes="welcome-text"),
                Button("Start Exploring", variant="primary", id="start", disabled=True),
            ]
        
        yield Vertical(*common_widgets, *action_widgets, id="welcome_dialog")

    def update_status(self, msg, color="yellow"):
        lbl = self.query_one("#loading_status")
        lbl.update(msg)
        lbl.styles.color = color

    def enable_start_button(self):
        btn = self.query_one("#start")
        btn.disabled = False
        btn.focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.app.pop_screen()
    
    def on_key(self, event: Key) -> None:
        self.app.pop_screen()
        event.stop()

    def on_status_update(self, message: StatusUpdate) -> None:
        self.update_status(message.message, message.color)

    def on_loading_complete(self, message: LoadingComplete) -> None:
        self.enable_start_button()

class EPGSelectionScreen(ModalScreen):
    """Screen to select an EPG from a list."""
    def __init__(self, epg_list):
        self.epg_list = sorted(epg_list)
        super().__init__()
        
    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("Select EPG", classes="header"),
            Input(placeholder="Type to filter...", id="epg_filter"),
            ListView(id="epg_list"),
            Button("Cancel", variant="error", id="cancel"),
            id="epg_dialog"
        )
    
    def on_mount(self):
        lv = self.query_one(ListView)
        for epg in self.epg_list:
            li = ListItem(Label(epg))
            li.epg_name = epg
            lv.append(li)
        self.query_one(Input).focus()

    def on_input_changed(self, event: Input.Changed):
        filter_text = event.value.lower()
        lv = self.query_one(ListView)
        lv.clear()
        for epg in self.epg_list:
            if filter_text in epg.lower():
                li = ListItem(Label(epg))
                li.epg_name = epg
                lv.append(li)
    
    def on_list_view_selected(self, event: ListView.Selected):
        self.dismiss(getattr(event.item, "epg_name", None))

    def on_key(self, event: Key) -> None:
        if event.key == "down":
            if self.query_one(Input).has_focus:
                self.query_one(ListView).focus()
                lv = self.query_one(ListView)
                if len(lv.children) > 0:
                    lv.index = 0
                event.stop()
        elif event.key == "up":
            lv = self.query_one(ListView)
            if lv.has_focus and lv.index == 0:
                self.query_one(Input).focus()
                event.stop()
        elif event.key == "escape":
            self.dismiss(None)
            event.stop()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

class PortDetailsScreen(ModalScreen):
    """Screen to show detailed port attributes."""
    
    BINDINGS = [
        ("q", "close", "Close"),
        ("escape", "close", "Close"),
    ]

    def __init__(self, port_attrs):
        self.port_attrs = port_attrs
        super().__init__()

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("Port Details", classes="header"),
            DataTable(id="port_table"),
            Button("Close", variant="primary", id="close"),
            id="port_details_dialog"
        )

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Attribute", "Value")
        table.cursor_type = "row"
        table.zebra_stripes = True
        
        key_attrs = ['id', 'adminSt', 'usage', 'speed', 'mtu', 'switchingSt', 'dn']
        
        for key in key_attrs:
            if key in self.port_attrs:
                table.add_row(Text(key, style="bold cyan"), str(self.port_attrs[key]))
        
        for key, value in sorted(self.port_attrs.items()):
            if key not in key_attrs:
                table.add_row(Text(key, style="bold"), str(value))
        
        table.focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss()

    def action_close(self) -> None:
        self.dismiss()

class PortSearchScreen(ModalScreen):
    """Screen to select search type for Port View."""
    def __init__(self, app_instance):
        self.main_app = app_instance
        super().__init__()

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("Search (Node Port View Only)", classes="header"),
            Button("Search EPG Ports", id="btn_epg"),
            Button("Show Fabric Ports", id="btn_fabric"),
            Button("Show Service Ports", id="btn_service"),
            Button("Reset View (Show All)", id="btn_reset"),
            Button("Cancel", variant="error", id="btn_cancel"),
            id="search_dialog"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn_epg":
            epg_list = list(self.main_app.maps.get('epg_to_ports', {}).keys())
            self.app.push_screen(EPGSelectionScreen(epg_list), self.on_epg_selected)
        elif btn_id == "btn_fabric":
            self.main_app.set_port_view_mode('fabric')
            self.dismiss()
        elif btn_id == "btn_service":
            self.main_app.set_port_view_mode('service')
            self.dismiss()
        elif btn_id == "btn_reset":
            self.main_app.set_port_view_mode('all')
            self.dismiss()
        else:
            self.dismiss()

    def on_epg_selected(self, selected_epg):
        if selected_epg:
            self.main_app.set_port_view_mode('epg', selected_epg)
        self.dismiss()

    def on_key(self, event: Key) -> None:
        if event.key == "down":
            self.focus_next()
        elif event.key == "up":
            self.focus_previous()
        elif event.key == "escape":
            self.dismiss()
            event.stop()

class QuitScreen(ModalScreen):
    """Screen with a dialog to quit."""

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("Are you sure you want to quit? (y/n)", id="question"),
            Button("Yes", variant="error", id="quit"),
            Button("No", variant="primary", id="cancel"),
            id="dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit":
            self.app.exit()
        else:
            self.dismiss()

    def on_mount(self) -> None:
        self.query_one("#quit").focus()

    def on_key(self, event: Key) -> None:
        if event.key == "y":
            self.app.exit()
            event.stop()
        elif event.key == "n":
            self.dismiss()
            event.stop()
        elif event.key in ("left", "right", "up", "down"):
            if self.query_one("#quit").has_focus:
                self.query_one("#cancel").focus()
            else:
                self.query_one("#quit").focus()
        elif event.key == "enter":
            if self.query_one("#quit").has_focus:
                self.app.exit()
            elif self.query_one("#cancel").has_focus:
                self.dismiss()
            event.stop()

class AciTreeViewerApp(App):
    """A Textual app to view ACI topology."""

    ENABLE_COMMAND_PALETTE = False

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("q", "quit", "Quit"),
        ("s", "search", "Search"),
        ("w", "save_report", "Save Report"),
    ]

    TITLE = "ACI Tree Viewer"
    CSS = """
    Screen {
        layout: vertical;
        background: black;
    }
    #main-container {
        layout: horizontal;
        height: 1fr;
    }
    #tree-pane {
        height: 1fr;
        width: 100%;
        background: black;
    }
    #stats-panel {
        dock: bottom;
        height: auto;
        min-height: 3;
        background: #1a1a1a;
        color: #eeeeee;
        border-top: solid $primary;
        padding: 1 2;
        text-align: center;
        text-style: bold;
    }
    Tree {
        background: black;
        color: white;
        width: 100%;
        height: 100%;
        border: round white;
    }
    Tabs {
        height: 4;
        background: black;
        border-bottom: solid $primary;
    }
    Tab {
        height: 3;
        padding: 0 2;
        content-align: center middle;
        border: heavy #666666;
        background: #333333;
        color: #ffffff;
        text-style: bold;
    }
    Tab.-active {
        background: $primary;
        color: #ffffff;
        border: heavy $primary-lighten-2;
        text-style: bold;
    }
    WelcomeScreen {
        align: center middle;
        background: rgba(0,0,0,0.7);
    }
    PortSearchScreen, EPGSelectionScreen, PortDetailsScreen {
        align: center middle;
        background: rgba(0,0,0,0.7);
    }
    QuitScreen {
        align: center middle;
        background: rgba(0,0,0,0.7);
    }
    #welcome_dialog {
        padding: 1 2;
        width: 60;
        height: auto;
        border: round $primary;
        background: $surface;
    }
    .welcome-header {
        text-align: center;
        color: green;
        text-style: bold;
    }
    .welcome-text {
        text-align: center;
        color: white;
    }
    #loading_status {
        color: yellow;
        margin-bottom: 1;
    }
    #dialog {
        padding: 1 2;
        width: 36;
        height: auto;
        border: round $primary;
        background: $surface;
    }
    #question {
        margin-bottom: 1;
        text-align: center;
    }
    #dialog > Button {
        width: 100%;
        margin-top: 1;
    }
    #search_dialog {
        padding: 1 2;
        width: 40;
        height: auto;
        border: round $primary;
        background: $surface;
    }
    #search_dialog > Button {
        width: 100%;
        margin-top: 1;
    }
    #epg_dialog {
        padding: 1 2;
        width: 60;
        height: 80%;
        border: round $primary;
        background: $surface;
    }
    #port_details_dialog {
        padding: 1 2;
        width: 80;
        height: 80%;
        border: heavy $primary;
        background: $surface;
    }
    #port_table {
        height: 1fr;
        margin-bottom: 1;
        border: solid $secondary;
    }
    .details-text {
        color: white;
    }
    #epg_list {
        height: 1fr;
        border: solid $primary;
        margin-top: 1;
    }
    .header {
        text-align: center;
        text-style: bold;
        margin-bottom: 1;
    }
    """

    VIEW_CLASSES = {
        'network': [
            'fvTenant', 'fvCtx', 'fvBD', 'fvAEPg', 'fvSubnet',
            'l3extOut', 'l3extInstP', 'l3extSubnet',
            'fvRsCtx', 'fvRsBd', 'l3extRsEctx',
            'vzAny', 'vzRsAnyToProv', 'vzRsAnyToCons',
            'ipRouteP', 'ipNexthopP', 'healthInst', 'faultInst',
            'vnsRsAbsGraphAtt', 'fvRsProv', 'fvRsCons', 'l3extRsProv', 'l3extRsCons', 'vzBrCP', 'vzSubj', 'l3extLNodeP', 'l3extRsNodeL3OutAtt'
        ],
        'contract': [
            'fvTenant', 'fvAEPg', 'l3extInstP',
            'fvRsProv', 'fvRsCons', 'l3extRsProv', 'l3extRsCons',
            'vzBrCP', 'vzSubj', 'vzAny', 'vzRsAnyToProv', 'vzRsAnyToCons',
            'healthInst', 'faultInst', 'fvSubnet', 'l3extSubnet', 'ipRouteP', 'fvRsBd', 'fvRsCtx', 'l3extRsEctx'
        ],
        'port': [
            'fabricNode', 'fabricVpcRT', 'fvRsPathAtt',
            'l3extRsPathL3OutAtt', 'lldpAdjEp', 'vnsRsCIfPathAtt',
            'fvTenant', 'fvAEPg', 'l3extInstP',
            'l1PhysIf', 'fabricNodePEp'
        ],
        'global_contract': [
            'fvTenant', 'fvAEPg', 'l3extInstP',
            'fvRsProv', 'fvRsCons', 'l3extRsProv', 'l3extRsCons',
            'vzBrCP', 'vzSubj', 'vzAny', 'vzRsAnyToProv', 'vzRsAnyToCons',
            'healthInst', 'faultInst', 'fvSubnet', 'l3extSubnet', 'ipRouteP', 'fvRsBd', 'fvRsCtx', 'l3extRsEctx'
        ]
    }

    def __init__(self, viewer):
        super().__init__()
        self.viewer = viewer
        self.views = ['network', 'contract', 'global_contract', 'port', 'help']
        self.current_view = 'network'
        self.data = {}
        self.maps = {}
        self.port_view_mode = 'all' # all, epg, fabric, service
        self.selected_epg_for_view = None
        self.last_refresh_time = 0
        self.view_states = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Tabs(
            Tab("Tenant Network View", id="network"),
            Tab("Tenant Contract View", id="contract"),
            Tab("Contract View", id="global_contract"),
            Tab("Node Port View", id="port"),
            Tab("Help", id="help"),
        )
        with Container(id="tree-pane"):
            yield TextualTree("ACI Topology", id="tree")
            yield Static("", id="stats-panel")
        yield Footer()

    def on_mount(self) -> None:
        """Called when app starts."""
        self.sub_title = "Welcome - Select a view"
        self.push_screen(WelcomeScreen())
        self.query_one(Tabs).focus()
        self.run_worker(self.load_initial_data, thread=True)

    def load_initial_data(self):
        self.screen.post_message(StatusUpdate("Fetching data from APIC..."))
        self.data = self.viewer._fetch_all_data()
        
        self.screen.post_message(StatusUpdate("Processing data..."))
        self.maps = self.viewer._process_mappings(self.data)
        
        self.screen.post_message(StatusUpdate("Data Loaded! Ready.", "green"))
        self.screen.post_message(LoadingComplete())
        self.call_from_thread(self.build_tree)

    def build_tree(self) -> None:
        """Fetches data and dispatches to the correct tree builder."""
        view_map = {'network': 'Tenant Network View', 'contract': 'Tenant Contract View', 'global_contract': 'Contract View', 'port': 'Node Port View'}
        
        if not self.data or not self.maps:
            self.sub_title = f"Loading {view_map.get(self.current_view, 'Unknown')} data..."
            return

        self.sub_title = f"View: {view_map.get(self.current_view, 'Unknown')} | Last updated: {datetime.now().strftime('%H:%M:%S')}"
        
        # Data is already loaded by load_initial_data or refresh
        # Just build the tree using cached data
        
        if self.current_view == 'network':
            self._build_network_tree()
        elif self.current_view == 'contract':
            self._build_contract_tree()
        elif self.current_view == 'global_contract':
            self._build_global_contract_tree()
        elif self.current_view == 'port':
            self._build_port_tree()

    def _get_key(self, data):
        """Convert node data to a hashable key."""
        if isinstance(data, dict):
            return tuple(sorted(data.items()))
        return data

    def save_state(self):
        """Save the current tree state (expanded nodes and cursor)."""
        if not self.data:
            return

        tree = self.query_one("#tree", TextualTree)
        if not tree.root or not tree.root.children:
            return

        expanded_nodes = set()
        
        def _collect_expanded(node):
            if node.is_expanded and node.data:
                expanded_nodes.add(self._get_key(node.data))
            for child in node.children:
                _collect_expanded(child)
        
        if tree.root:
             _collect_expanded(tree.root)
        
        cursor_node = tree.cursor_node
        cursor_data = self._get_key(cursor_node.data) if cursor_node and cursor_node.data else None
        
        self.view_states[self.current_view] = {
            'expanded': expanded_nodes,
            'cursor': cursor_data
        }

    def _build_network_tree(self) -> None:
        """Fetches data and builds/refreshes the tree view, preserving state."""
        tree = self.query_one("#tree", TextualTree)
        
        # Update Stats
        t_count = len(self.data.get('fvTenant', []))
        v_count = len(self.data.get('fvCtx', []))
        bd_count = len(self.data.get('fvBD', []))
        epg_count = len(self.data.get('fvAEPg', []))
        l3_count = len(self.data.get('l3extOut', []))
        self.query_one("#stats-panel").update(f"Network Stats: Tenants: {t_count} | VRFs: {v_count} | BDs: {bd_count} | EPGs: {epg_count} | L3Outs: {l3_count}")

        # Use view_states for state preservation
        state = self.view_states.get(self.current_view)
        has_state = state is not None
        expanded_nodes = state['expanded'] if has_state else set()
        cursor_data = state['cursor'] if has_state else None

        tree.clear()
        tree.show_root = False
        tree.root.expand()
        
        data = self.data
        maps = self.maps
        vpc_pairs = maps.get('vpc_pairs', {})
        def get_cont_label(name, tenant_name):
            direction = maps['contract_info'].get((tenant_name, name))
            if not direction: direction = maps['contract_info'].get(('common', name), 'Bi')
            return f"{name} ({direction})"

        data_to_node_map = {}

        for t in data['fvTenant']:
            t_name, t_dn = t['fvTenant']['attributes']['name'], t['fvTenant']['attributes']['dn']
            health_status = self.viewer._format_health_status(t_dn, maps['health_map'], maps['fault_map'])
            t_node = tree.root.add(
                f"[bold]Tenant:[/bold] {t_name}{health_status}",
                data=t_dn,
                expand=has_state and (self._get_key(t_dn) in expanded_nodes)
            )
            data_to_node_map[t_dn] = t_node
            
            tenant_vrfs = [v for v in data['fvCtx'] if v['fvCtx']['attributes']['dn'].startswith(t_dn)]
            if not tenant_vrfs:
                t_node.add_leaf("No VRFs found.")

            for v in tenant_vrfs:
                v_attr = v['fvCtx']['attributes'] 
                v_dn = v_attr['dn']
                v_name = v_attr['name']
                health_status = self.viewer._format_health_status(v_dn, maps['health_map'], maps['fault_map'])
                v_node = t_node.add(
                    f"[bold]VRF:[/bold] {v_name} [dim](VNID: {v_attr.get('scope', 'N/A')}, pcTag: {self.viewer._format_tag(v_attr.get('pcTag', 'N/A'))})[/dim]{health_status}",
                    data=v_dn,
                    expand=has_state and (self._get_key(v_dn) in expanded_nodes)
                )
                data_to_node_map[v_dn] = v_node

                # vzAny
                vzany_dn = f"{v_dn}/any"
                vz_conts = maps['total_conts'].get(vzany_dn)
                if vz_conts and (vz_conts['prov'] or vz_conts['cons']):
                    vzany_node_dn = f"{v_dn}/vzany_node"
                    vz_node_t = v_node.add(
                        "[bold magenta]vzAny (VRF Contracts)[/bold magenta]",
                        data=vzany_node_dn,
                        expand=has_state and (self._get_key(vzany_node_dn) in expanded_nodes)
                    )
                    data_to_node_map[vzany_node_dn] = vz_node_t
                    for p in vz_conts['prov']:
                        vz_node_t.add_leaf(f"Provides: [cyan]{get_cont_label(p, t_name)}[/cyan]")
                    for c in vz_conts['cons']:
                        vz_node_t.add_leaf(f"Consumes: [cyan]{get_cont_label(c, t_name)}[/cyan]")

                # Internal
                internal_node_dn = f"{v_dn}/internal_node"
                internal_node = v_node.add(
                    "[bold]Internal Network & Security[/bold]",
                    data=internal_node_dn,
                    expand=has_state and (self._get_key(internal_node_dn) in expanded_nodes)
                )
                data_to_node_map[internal_node_dn] = internal_node
                t_bds = [b for b in data['fvBD'] if b['fvBD']['attributes']['dn'].startswith(t_dn) and maps['bd_to_vrf'].get(b['fvBD']['attributes']['dn']) == v_name]
                if not t_bds:
                    internal_node.add_leaf("No BDs found.")
                for b in t_bds:
                    bd_attr = b['fvBD']['attributes']
                    bd_name = bd_attr['name']
                    bd_dn = bd_attr['dn']
                    health_status = self.viewer._format_health_status(bd_dn, maps['health_map'], maps['fault_map'])
                    bd_node = internal_node.add(
                        f"[bold]BD:[/bold] {bd_name} [dim](pcTag: {self.viewer._format_tag(bd_attr.get('pcTag', 'N/A'))})[/dim]{health_status}",
                        data=bd_dn,
                        expand=has_state and (self._get_key(bd_dn) in expanded_nodes)
                    )
                    data_to_node_map[bd_dn] = bd_node
                    
                    epg_found = False
                    for rs in data['fvRsBd']:
                        rs_attr = rs['fvRsBd']['attributes']
                        if rs_attr['tnFvBDName'] == bd_name and rs_attr['dn'].startswith(t_dn):
                            epg_found = True
                            epg_dn = rs_attr['dn'].replace('/rsbd', '')
                            epg_name = epg_dn.split('epg-')[-1]
                            epg_obj = next((e for e in data['fvAEPg'] if e['fvAEPg']['attributes']['dn'] == epg_dn), None)
                            pctag = self.viewer._format_tag(epg_obj['fvAEPg']['attributes'].get('pcTag', 'N/A')) if epg_obj else 'N/A'
                            
                            health_status = self.viewer._format_health_status(epg_dn, maps['health_map'], maps['fault_map'])
                            epg_node = bd_node.add(
                                f"[bold]EPG:[/bold] {epg_name} [dim](pcTag: {pctag})[/dim]{health_status}",
                                data=epg_dn,
                                expand=has_state and (self._get_key(epg_dn) in expanded_nodes)
                            )
                            data_to_node_map[epg_dn] = epg_node
                            conts = maps['total_conts'].get(epg_dn, {"prov": [], "cons": []})
                            for p in conts['prov']:
                                g = f" [bold red][Graph: {maps['cont_to_graph'][p]}][/bold red]" if p in maps['cont_to_graph'] else ""
                                epg_node.add_leaf(f"Provides: [cyan]{get_cont_label(p, t_name)}[/cyan]{g}")
                            for c in conts['cons']:
                                g = f" [bold red][Graph: {maps['cont_to_graph'][c]}][/bold red]" if c in maps['cont_to_graph'] else ""
                                epg_node.add_leaf(f"Consumes: [cyan]{get_cont_label(c, t_name)}[/cyan]{g}")
                    if not epg_found:
                        bd_node.add_leaf("No EPGs found.")

                # External
                external_node_dn = f"{v_dn}/external_node"
                external_node = v_node.add(
                    "[bold]External Connectivity (L3Out)[/bold]",
                    data=external_node_dn,
                    expand=has_state and (self._get_key(external_node_dn) in expanded_nodes)
                )
                data_to_node_map[external_node_dn] = external_node
                t_l3s = [l for l in data['l3extOut'] if l['l3extOut']['attributes']['dn'].startswith(t_dn) and maps['l3_to_vrf'].get(l['l3extOut']['attributes']['dn']) == v_name]
                if not t_l3s:
                    external_node.add_leaf("No L3Outs found.")
                for l in t_l3s:
                    l_dn = l['l3extOut']['attributes']['dn']
                    all_ads = list(set(maps['vrf_public_subnets'].get(v_name, []))) + maps['l3out_ext_info'].get(l_dn, [])
                    subnets_str = ", ".join(all_ads) if all_ads else "Private Only"
                    health_status = self.viewer._format_health_status(l_dn, maps['health_map'], maps['fault_map'])
                    l3_node = external_node.add(
                        f"[bold]L3Out:[/bold] {l['l3extOut']['attributes']['name']}{health_status}",
                        data=l_dn,
                        expand=has_state and (self._get_key(l_dn) in expanded_nodes)
                    )
                    data_to_node_map[l_dn] = l3_node
                    l3_node.add_leaf(f"Advertised: [green]{subnets_str}[/green]")
                    
                    s_routes = maps['l3out_static_routes'].get(l_dn, [])
                    if s_routes:
                        sr_node_dn = f"{l_dn}/static_routes"
                        sr_node = l3_node.add(
                            "[bold]Static Routes[/bold]",
                            data=sr_node_dn,
                            expand=has_state and (self._get_key(sr_node_dn) in expanded_nodes)
                        )
                        data_to_node_map[sr_node_dn] = sr_node
                        
                        nodes_routes = defaultdict(list)
                        for sr in s_routes:
                            nodes_routes[sr['node']].append(sr)

                        for node_id, routes in sorted(nodes_routes.items()):
                            node_label = f"[bold]Node {node_id}[/bold]"
                            if node_id in vpc_pairs:
                                node_label += f" [magenta](vPC Peer: {vpc_pairs[node_id]})[/magenta]"

                            node_dn = f"{sr_node_dn}/node-{node_id}"
                            node_branch = sr_node.add(
                                node_label,
                                data=node_dn,
                                expand=has_state and (self._get_key(node_dn) in expanded_nodes)
                            )
                            data_to_node_map[node_dn] = node_branch
                            
                            for sr in sorted(routes, key=lambda x: x['prefix']):
                                nexthops = ", ".join(sorted(sr['nexthops']))
                                node_branch.add_leaf(
                                    f"[cyan]{sr['prefix']}[/cyan] via [yellow]{nexthops}[/yellow]", 
                                    data=sr['dn']
                                )

                    ext_epg_found = False
                    for instp in data['l3extInstP']:
                        i_attr = instp['l3extInstP']['attributes']
                        if i_attr['dn'].startswith(l_dn):
                            ext_epg_found = True
                            i_dn = i_attr['dn']
                            health_status = self.viewer._format_health_status(i_dn, maps['health_map'], maps['fault_map'])
                            ext_epg_node = l3_node.add(
                                f"[bold]External EPG:[/bold] {i_attr['name']} [dim](pcTag: {self.viewer._format_tag(i_attr.get('pcTag', 'N/A'))})[/dim]{health_status}",
                                data=i_dn,
                                expand=has_state and (self._get_key(i_dn) in expanded_nodes)
                            )
                            data_to_node_map[i_dn] = ext_epg_node
                            
                            for sub in maps['instp_subnets'].get(i_dn, []):
                                scope_str = self.viewer._format_scope(sub.get('scope', ''))
                                ext_epg_node.add_leaf(f"Subnet: [bold yellow]{sub['ip']}[/bold yellow] [dim](pcTag: {self.viewer._format_tag(sub.get('pcTag', 'N/A'))}, Scope: {scope_str})[/dim]")

                            i_conts = maps['total_conts'].get(i_dn, {"prov": [], "cons": []})
                            for p in i_conts['prov']:
                                g = f" [bold red][Graph: {maps['cont_to_graph'][p]}][/bold red]" if p in maps['cont_to_graph'] else ""
                                ext_epg_node.add_leaf(f"Provides: [cyan]{get_cont_label(p, t_name)}[/cyan]{g}")
                            for c in i_conts['cons']:
                                g = f" [bold red][Graph: {maps['cont_to_graph'][c]}][/bold red]" if c in maps['cont_to_graph'] else ""
                                ext_epg_node.add_leaf(f"Consumes: [cyan]{get_cont_label(c, t_name)}[/cyan]{g}")
                    if not ext_epg_found:
                        l3_node.add_leaf("No External EPGs found.")
        
        # Restore cursor position
        if cursor_data and self._get_key(cursor_data) in data_to_node_map:
            tree.select_node(data_to_node_map[self._get_key(cursor_data)])

        tree.focus()

    def _build_contract_tree(self) -> None:
        """Builds the contract-centric tree view."""
        tree = self.query_one("#tree", TextualTree)
        
        state = self.view_states.get(self.current_view)
        has_state = state is not None
        expanded_nodes = state['expanded'] if has_state else set()
        cursor_data = state['cursor'] if has_state else None
        
        data_to_node_map = {}

        tree.clear()
        tree.show_root = False
        tree.root.expand()

        maps = self.maps
        app_map = maps['app_centric_map']
        health_map = maps['health_map']
        fault_map = maps['fault_map']
        epg_to_bd = maps['epg_to_bd']
        vrf_to_epgs = maps.get('vrf_to_epgs', {})

        tenant_map = defaultdict(list)
        for (tenant, contract), epgs in app_map.items():
            tenant_map[tenant].append((contract, epgs))

        tenants_to_display = sorted(tenant_map.keys())

        total_contracts = sum(len(contracts) for contracts in tenant_map.values())
        displayed_contracts = sum(len(tenant_map[t]) for t in tenants_to_display)
        self.query_one("#stats-panel").update(f"Tenant Contract Stats: Tenants: {len(tenants_to_display)} | Contracts Displayed: {displayed_contracts} (Total: {total_contracts})")

        def get_network_info(dn):
            """Returns a list of network info (Subnets/Routes) for an EPG or L3Out."""
            info = []
            # 1. EPG Case
            if '/epg-' in dn:
                bd_dn = epg_to_bd.get(dn)
                if bd_dn:
                    subnets = sorted(maps['bd_subnets'].get(bd_dn, []))
                    bd_name = bd_dn.split('/bd-')[-1]
                    for sub in subnets:
                        info.append(f"[yellow]{sub}[/yellow] (BD: {bd_name})")
            # 2. L3Out Case
            elif '/instP-' in dn:
                # External Subnets
                for sub in sorted(maps['instp_subnets'].get(dn, []), key=lambda s: s['ip']):
                    info.append(f"[yellow]{sub['ip']}[/yellow] (Ext EPG Subnet)")
                # Static Routes (Associated with the L3Out of this InstP)
                l3out_dn = dn.split('/instP-')[0]
                for route in sorted(maps['l3out_static_routes'].get(l3out_dn, []), key=lambda r: r['prefix']):
                    node_info = f" [dim](Node: {route['node']})[/dim]" if route.get('node') else ""
                    info.append(f"[yellow]{route['prefix']}[/yellow] (Static Route){node_info}")
            # 3. vzAny Case
            elif dn.endswith('/any'):
                info.append("[dim]Applies to all EPGs in VRF[/dim]")
            return info

        def get_vrf_info(dn):
            """Returns (Tenant, VRF Name) for an EPG or L3Out."""
            # EPG -> BD -> VRF
            if '/epg-' in dn:
                bd_dn = epg_to_bd.get(dn)
                if bd_dn:
                    vrf_name = maps['bd_to_vrf'].get(bd_dn, "Unknown VRF")
                    # BD DN: uni/tn-X/BD-Y -> Tenant is X
                    tenant_match = re.match(r'uni/tn-([^/]+)', bd_dn)
                    tenant_name = tenant_match.group(1) if tenant_match else "Unknown"
                    return tenant_name, vrf_name
            # L3Out -> VRF
            elif '/instP-' in dn:
                l3out_dn = dn.split('/instP-')[0]
                vrf_name = maps['l3_to_vrf'].get(l3out_dn, "Unknown VRF")
                tenant_match = re.match(r'uni/tn-([^/]+)', l3out_dn)
                tenant_name = tenant_match.group(1) if tenant_match else "Unknown"
                return tenant_name, vrf_name
            # vzAny -> VRF
            elif dn.endswith('/any'):
                tenant_match = re.match(r'uni/tn-([^/]+)', dn)
                vrf_match = re.search(r'/ctx-([^/]+)/', dn)
                tenant_name = tenant_match.group(1) if tenant_match else "Unknown"
                vrf_name = vrf_match.group(1) if vrf_match else "Unknown"
                return tenant_name, vrf_name
            
            return "Unknown", "Unknown"

        for tenant in tenants_to_display:
            t_dn = f"uni/tn-{tenant}"
            health_status = self.viewer._format_health_status(t_dn, health_map, fault_map)
            t_node = tree.root.add(
                f"[bold]Tenant:[/bold] {tenant}{health_status}",
                data=t_dn,
                expand=has_state and (self._get_key(t_dn) in expanded_nodes)
            )
            data_to_node_map[t_dn] = t_node
            
            contracts = sorted(tenant_map[tenant], key=lambda x: x[0])
            if not contracts: t_node.add_leaf("No contract relationships found.")

            for contract, epgs in contracts:
                # Determine Source and Scope
                scope = maps['contract_scopes'].get((tenant, contract))
                source_tenant = tenant
                if not scope:
                    scope = maps['contract_scopes'].get(('common', contract))
                    if scope: source_tenant = 'common'
                    else: scope = 'unknown'

                if source_tenant == tenant and not scope:
                    owners = maps['contract_name_to_tenants'].get(contract)
                    if owners:
                        source_tenant = list(owners)[0]
                        scope = maps['contract_scopes'].get((source_tenant, contract), 'unknown')

                direction = maps['contract_info'].get((tenant, contract), 'Bi')
                
                contract_type = "Local Contract" if source_tenant == tenant else "Remote Contract"
                source_info = ""
                if source_tenant != tenant:
                    source_info = f", Source: [bold magenta]{source_tenant}[/bold magenta]"
                
                label = f"Contract: [cyan]{contract}[/cyan] ({direction}, {contract_type}, Scope: {scope}{source_info})"
                contract_dn = f"uni/tn-{source_tenant}/brc-{contract}"
                c_node = t_node.add(label, data=contract_dn, expand=has_state and (self._get_key(contract_dn) in expanded_nodes))
                data_to_node_map[contract_dn] = c_node

                # Providers Section
                prov_node_dn = f"{contract_dn}/providers"
                all_provs = maps['contract_providers'].get((source_tenant, contract), set())
                prov_node = c_node.add(f"[green]Providers[/green] ({len(all_provs)})", data=prov_node_dn, expand=has_state and (prov_node_dn in expanded_nodes))
                
                if not all_provs:
                    prov_node.add_leaf("[dim]No Providers Configured[/dim]")
                else:
                    prov_groups = defaultdict(list)
                    for p_tenant, p_epg, p_dn in all_provs:
                        _, p_vrf = get_vrf_info(p_dn)
                        prov_groups[(p_tenant, p_vrf)].append((p_epg, p_dn))
                    
                    for (p_tenant, p_vrf), providers in sorted(prov_groups.items()):
                        loc_str = " [bold magenta](Local)[/bold magenta]" if p_tenant == tenant else ""
                        group_dn = f"{prov_node_dn}/group-{p_tenant}-{p_vrf}"
                        group_node = prov_node.add(f"[bold]Tenant:[/bold] {p_tenant}{loc_str} -> [bold]VRF:[/bold] {p_vrf}", data=group_dn, expand=has_state and (self._get_key(group_dn) in expanded_nodes))
                        data_to_node_map[group_dn] = group_node
                        for epg_name, epg_dn in sorted(providers):
                            health_status = self.viewer._format_health_status(epg_dn, health_map, fault_map)
                            label_name = f"[bold red]{epg_name}[/bold red]" if epg_dn.endswith('/any') else epg_name
                            epg_node = group_node.add(f"EPG: {label_name}{health_status}", data=epg_dn, expand=has_state and (self._get_key(epg_dn) in expanded_nodes))
                            data_to_node_map[epg_dn] = epg_node
                            
                            if epg_dn.endswith('/any'):
                                m = re.match(r'uni/tn-([^/]+)/ctx-([^/]+)/any', epg_dn)
                                if m:
                                    t, v = m.groups()
                                    member_epgs = vrf_to_epgs.get((t, v), [])
                                    if member_epgs:
                                        vz_node = epg_node.add(f"[dim]Expanded EPGs in VRF {v}:[/dim]")
                                        for mem_name, mem_dn in sorted(member_epgs):
                                            vz_node.add_leaf(f"EPG: {mem_name}", data=mem_dn)
                            
                            net_info = get_network_info(epg_dn)
                            for info in net_info:
                                epg_node.add_leaf(f"Network: {info}")

                # Consumers Section (Grouped by Tenant -> VRF)
                cons_node_dn = f"{contract_dn}/consumers"
                all_cons = maps['contract_consumers'].get((source_tenant, contract), set())
                
                if source_tenant == tenant:
                    filtered_cons = list(all_cons)
                else:
                    filtered_cons = [c for c in all_cons if c[0] == tenant]

                cons_node = c_node.add(f"[yellow]Consumers[/yellow] ({len(filtered_cons)})", data=cons_node_dn, expand=has_state and (self._get_key(cons_node_dn) in expanded_nodes))
                data_to_node_map[cons_node_dn] = cons_node
                if filtered_cons:
                    # Group consumers by (Tenant, VRF)
                    cons_groups = defaultdict(list)
                    for c_tenant, c_epg, c_dn in filtered_cons:
                        _, c_vrf = get_vrf_info(c_dn)
                        cons_groups[(c_tenant, c_vrf)].append((c_epg, c_dn))

                    for (c_tenant, c_vrf), consumers in sorted(cons_groups.items()):
                        loc_str = " [bold magenta](Local)[/bold magenta]" if c_tenant == tenant else ""
                        group_dn = f"{cons_node_dn}/group-{c_tenant}-{c_vrf}"
                        group_node = cons_node.add(f"[bold]Tenant:[/bold] {c_tenant}{loc_str} -> [bold]VRF:[/bold] {c_vrf}", data=group_dn, expand=has_state and (self._get_key(group_dn) in expanded_nodes))
                        data_to_node_map[group_dn] = group_node
                        for epg_name, epg_dn in consumers:
                            health_status = self.viewer._format_health_status(epg_dn, health_map, fault_map)
                            label_name = f"[bold red]{epg_name}[/bold red]" if epg_dn.endswith('/any') else epg_name
                            epg_node = group_node.add(f"EPG: {label_name}{health_status}", data=epg_dn, expand=has_state and (self._get_key(epg_dn) in expanded_nodes))
                            data_to_node_map[epg_dn] = epg_node
                            
                            if epg_dn.endswith('/any'):
                                m = re.match(r'uni/tn-([^/]+)/ctx-([^/]+)/any', epg_dn)
                                if m:
                                    t, v = m.groups()
                                    member_epgs = vrf_to_epgs.get((t, v), [])
                                    if member_epgs:
                                        vz_node = epg_node.add(f"[dim]Expanded EPGs in VRF {v}:[/dim]")
                                        for mem_name, mem_dn in sorted(member_epgs):
                                            vz_node.add_leaf(f"EPG: {mem_name}", data=mem_dn)

                            # Network Info
                            net_info = get_network_info(epg_dn)
                            for info in net_info:
                                epg_node.add_leaf(f"Network: {info}")

                else: cons_node.add_leaf("[dim]None[/dim]")
        
        if cursor_data and self._get_key(cursor_data) in data_to_node_map:
            tree.select_node(data_to_node_map[self._get_key(cursor_data)])

        tree.focus()

    def _build_global_contract_tree(self) -> None:
        """Builds the global contract-centric tree view (Tenant agnostic)."""
        tree = self.query_one("#tree", TextualTree)
        
        state = self.view_states.get(self.current_view)
        has_state = state is not None
        expanded_nodes = state['expanded'] if has_state else set()
        cursor_data = state['cursor'] if has_state else None
        
        data_to_node_map = {}

        tree.clear()
        tree.show_root = False
        tree.root.expand()

        maps = self.maps
        contract_providers = maps['contract_providers']
        contract_consumers = maps['contract_consumers']
        health_map = maps['health_map']
        fault_map = maps['fault_map']
        epg_to_bd = maps['epg_to_bd']
        vrf_to_epgs = maps.get('vrf_to_epgs', {})

        # Helper to get network info (same as in _build_contract_tree)
        def get_network_info(dn):
            info = []
            if '/epg-' in dn:
                bd_dn = epg_to_bd.get(dn)
                if bd_dn:
                    subnets = sorted(maps['bd_subnets'].get(bd_dn, []))
                    bd_name = bd_dn.split('/bd-')[-1]
                    for sub in subnets:
                        info.append(f"[yellow]{sub}[/yellow] (BD: {bd_name})")
            elif '/instP-' in dn:
                for sub in sorted(maps['instp_subnets'].get(dn, []), key=lambda s: s['ip']):
                    info.append(f"[yellow]{sub['ip']}[/yellow] (Ext EPG Subnet)")
                l3out_dn = dn.split('/instP-')[0]
                for route in sorted(maps['l3out_static_routes'].get(l3out_dn, []), key=lambda r: r['prefix']):
                    node_info = f" [dim](Node: {route['node']})[/dim]" if route.get('node') else ""
                    info.append(f"[yellow]{route['prefix']}[/yellow] (Static Route){node_info}")
            elif dn.endswith('/any'):
                info.append("[dim]Applies to all EPGs in VRF[/dim]")
            return info

        def get_vrf_info(dn):
            if '/epg-' in dn:
                bd_dn = epg_to_bd.get(dn)
                if bd_dn:
                    vrf_name = maps['bd_to_vrf'].get(bd_dn, "Unknown VRF")
                    tenant_match = re.match(r'uni/tn-([^/]+)', bd_dn)
                    tenant_name = tenant_match.group(1) if tenant_match else "Unknown"
                    return tenant_name, vrf_name
            elif '/instP-' in dn:
                l3out_dn = dn.split('/instP-')[0]
                vrf_name = maps['l3_to_vrf'].get(l3out_dn, "Unknown VRF")
                tenant_match = re.match(r'uni/tn-([^/]+)', l3out_dn)
                tenant_name = tenant_match.group(1) if tenant_match else "Unknown"
                return tenant_name, vrf_name
            elif dn.endswith('/any'):
                tenant_match = re.match(r'uni/tn-([^/]+)', dn)
                vrf_match = re.search(r'/ctx-([^/]+)/', dn)
                tenant_name = tenant_match.group(1) if tenant_match else "Unknown"
                vrf_name = vrf_match.group(1) if vrf_match else "Unknown"
                return tenant_name, vrf_name
            return "Unknown", "Unknown"

        # Collect all unique contracts from providers and consumers
        all_contracts = set(contract_providers.keys()) | set(contract_consumers.keys())
        
        # Sort by Tenant then Contract Name
        sorted_contracts = sorted(list(all_contracts), key=lambda x: (x[0], x[1]))

        total_prov = sum(len(contract_providers.get(c, [])) for c in all_contracts)
        total_cons = sum(len(contract_consumers.get(c, [])) for c in all_contracts)

        self.query_one("#stats-panel").update(f"Global Contract Stats: Contracts: {len(all_contracts)} | Total Providers: {total_prov} | Total Consumers: {total_cons}")

        for tenant, contract in sorted_contracts:
            scope = maps['contract_scopes'].get((tenant, contract), 'unknown')
            direction = maps['contract_info'].get((tenant, contract), 'Bi')
            
            label = f"Contract: [cyan]{contract}[/cyan] [dim](Tenant: {tenant}, Scope: {scope}, {direction})[/dim]"
            contract_dn = f"uni/tn-{tenant}/brc-{contract}"
            c_node = tree.root.add(label, data=contract_dn, expand=has_state and (self._get_key(contract_dn) in expanded_nodes))
            data_to_node_map[contract_dn] = c_node

            # Providers
            provs = contract_providers.get((tenant, contract), set())
            prov_node_dn = f"{contract_dn}/providers"
            prov_node = c_node.add(
                f"[green]Providers[/green] ({len(provs)})",
                data=prov_node_dn,
                expand=has_state and (self._get_key(prov_node_dn) in expanded_nodes)
            )
            data_to_node_map[prov_node_dn] = prov_node
            if not provs:
                prov_node.add_leaf("[dim]No Providers Configured[/dim]")
            else:
                prov_groups = defaultdict(list)
                for p_tenant, p_epg, p_dn in provs:
                    _, p_vrf = get_vrf_info(p_dn)
                    prov_groups[(p_tenant, p_vrf)].append((p_epg, p_dn))
                
                for (p_tenant, p_vrf), providers in sorted(prov_groups.items()):
                    group_dn = f"{prov_node_dn}/group-{p_tenant}-{p_vrf}"
                    group_node = prov_node.add(f"[bold]Tenant:[/bold] {p_tenant} -> [bold]VRF:[/bold] {p_vrf}", data=group_dn, expand=has_state and (self._get_key(group_dn) in expanded_nodes))
                    data_to_node_map[group_dn] = group_node
                    for epg_name, epg_dn in sorted(providers):
                        health_status = self.viewer._format_health_status(epg_dn, health_map, fault_map)
                        label_name = f"[bold red]{epg_name}[/bold red]" if epg_dn.endswith('/any') else epg_name
                        epg_node = group_node.add(f"EPG: {label_name}{health_status}", data=epg_dn, expand=has_state and (self._get_key(epg_dn) in expanded_nodes))
                        data_to_node_map[epg_dn] = epg_node
                        
                        if epg_dn.endswith('/any'):
                            m = re.match(r'uni/tn-([^/]+)/ctx-([^/]+)/any', epg_dn)
                            if m:
                                t, v = m.groups()
                                member_epgs = vrf_to_epgs.get((t, v), [])
                                if member_epgs:
                                    vz_node = epg_node.add(f"[dim]Expanded EPGs in VRF {v}:[/dim]")
                                    for mem_name, mem_dn in sorted(member_epgs):
                                        vz_node.add_leaf(f"EPG: {mem_name}", data=mem_dn)

                        for info in get_network_info(epg_dn):
                            epg_node.add_leaf(f"Network: {info}")

            # Consumers
            cons = contract_consumers.get((tenant, contract), set())
            cons_node_dn = f"{contract_dn}/consumers"
            cons_node = c_node.add(
                f"[yellow]Consumers[/yellow] ({len(cons)})",
                data=cons_node_dn,
                expand=has_state and (self._get_key(cons_node_dn) in expanded_nodes)
            )
            data_to_node_map[cons_node_dn] = cons_node
            if not cons:
                cons_node.add_leaf("[dim]None[/dim]")
            else:
                cons_groups = defaultdict(list)
                for c_tenant, c_epg, c_dn in cons:
                    _, c_vrf = get_vrf_info(c_dn)
                    cons_groups[(c_tenant, c_vrf)].append((c_epg, c_dn))
                
                for (c_tenant, c_vrf), consumers in sorted(cons_groups.items()):
                    group_dn = f"{cons_node_dn}/group-{c_tenant}-{c_vrf}"
                    group_node = cons_node.add(f"[bold]Tenant:[/bold] {c_tenant} -> [bold]VRF:[/bold] {c_vrf}", data=group_dn, expand=has_state and (self._get_key(group_dn) in expanded_nodes))
                    data_to_node_map[group_dn] = group_node
                    for epg_name, epg_dn in sorted(consumers):
                        health_status = self.viewer._format_health_status(epg_dn, health_map, fault_map)
                        label_name = f"[bold red]{epg_name}[/bold red]" if epg_dn.endswith('/any') else epg_name
                        epg_node = group_node.add(f"EPG: {label_name}{health_status}", data=epg_dn, expand=has_state and (self._get_key(epg_dn) in expanded_nodes))
                        data_to_node_map[epg_dn] = epg_node
                        
                        if epg_dn.endswith('/any'):
                            m = re.match(r'uni/tn-([^/]+)/ctx-([^/]+)/any', epg_dn)
                            if m:
                                t, v = m.groups()
                                member_epgs = vrf_to_epgs.get((t, v), [])
                                if member_epgs:
                                    vz_node = epg_node.add(f"[dim]Expanded EPGs in VRF {v}:[/dim]")
                                    for mem_name, mem_dn in sorted(member_epgs):
                                        vz_node.add_leaf(f"EPG: {mem_name}", data=mem_dn)

                        for info in get_network_info(epg_dn):
                            epg_node.add_leaf(f"Network: {info}")

        if cursor_data and self._get_key(cursor_data) in data_to_node_map:
            tree.select_node(data_to_node_map[self._get_key(cursor_data)])

        tree.focus()

    def _build_port_tree(self) -> None:
        """Builds the port-centric tree view."""
        tree = self.query_one("#tree", TextualTree)
        
        state = self.view_states.get(self.current_view)
        has_state = state is not None
        expanded_nodes = state['expanded'] if has_state else set()
        cursor_data = state['cursor'] if has_state else None
        
        data_to_node_map = {}

        stats_panel = self.query_one("#stats-panel")
        tree.clear()

        maps = self.maps
        
        # Calculate Stats
        epg_to_ports = maps.get('epg_to_ports', {})
        fabric_ports = maps.get('fabric_ports', {})
        service_ports = maps.get('service_ports', {})

        epg_count = len(epg_to_ports)
        
        epg_connected_ports = set()
        for ports_list in epg_to_ports.values():
            for node, port, vlan in ports_list:
                epg_connected_ports.add((node, port))
        epg_port_count = len(epg_connected_ports)

        fabric_port_count = sum(len(ports) for ports in fabric_ports.values())
        service_port_count = sum(len(ports) for ports in service_ports.values())
        
        stats_panel.update(f"Port Statistics: Total EPGs: {epg_count} | EPG Ports: {epg_port_count} | Fabric Ports: {fabric_port_count} | Service Ports: {service_port_count}")
        
        filter_info = ""
        if self.port_view_mode == 'epg':
            filter_info = f" (Filter: EPG {self.selected_epg_for_view})"
        elif self.port_view_mode == 'fabric':
            filter_info = " (Filter: Fabric Ports)"
        elif self.port_view_mode == 'service':
            filter_info = " (Filter: Service Ports)"
        
        self.sub_title = f"View: Node Port View{filter_info} | Last updated: {datetime.now().strftime('%H:%M:%S')}"

        data = self.data
        port_map = maps.get('port_details_map', {})
        vpc_pairs = maps.get('vpc_pairs', {})
        
        nodes = sorted(data.get('fabricNode', []), key=lambda x: int(x['fabricNode']['attributes']['id']))
        node_id_to_name = {n['fabricNode']['attributes']['id']: n['fabricNode']['attributes']['name'] for n in nodes}

        tree.show_root = False
        tree.root.expand()

        # Determine relevant nodes based on filter
        relevant_nodes = None
        if self.port_view_mode == 'epg' and self.selected_epg_for_view:
            epg_ports = maps.get('epg_to_ports', {}).get(self.selected_epg_for_view, [])
            relevant_nodes = {p[0] for p in epg_ports}
        elif self.port_view_mode == 'fabric':
            relevant_nodes = set(maps.get('fabric_ports', {}).keys())
        elif self.port_view_mode == 'service':
            relevant_nodes = set(maps.get('service_ports', {}).keys())

        if not nodes:
            tree.root.add_leaf("No fabric nodes found.")
            return

        processed_nodes = set()

        def natural_sort_key(s):
            return [int(text) if text.isdigit() else text.lower() for text in re.split(r'(\d+)', s)]

        def get_node_port_items(node_id):
            items = []
            
            # Mode: EPG Filter
            if self.port_view_mode == 'epg' and self.selected_epg_for_view:
                epg_ports = maps.get('epg_to_ports', {}).get(self.selected_epg_for_view, [])
                # Filter ports for this node
                node_ports = [p for p in epg_ports if p[0] == node_id]
                
                # Group by port
                ports_grouped = defaultdict(list)
                for _, port, vlan in node_ports:
                    ports_grouped[port].append(vlan)
                
                for port, vlans in ports_grouped.items():
                    def render(parent, prefix, _port=port, _vlans=vlans, _node_id=node_id):
                        data = {'type': 'port', 'node': _node_id, 'port': _port}
                        is_expanded = has_state and (self._get_key(data) in expanded_nodes)
                        port_node = parent.add(f"{prefix}Port: [cyan]{_port}[/cyan]", data=data, expand=is_expanded)
                        data_to_node_map[self._get_key(data)] = port_node
                        
                        for vlan in sorted(_vlans):
                            if vlan == 'untagged':
                                port_node.add_leaf(f"EPG: {self.selected_epg_for_view}")
                            else:
                                port_node.add_leaf(f"VLAN: [yellow]{vlan}[/yellow] -> EPG: {self.selected_epg_for_view}")
                    items.append({'port': port, 'render': render})
            
            # Mode: Fabric Ports
            elif self.port_view_mode == 'fabric':
                fab_ports = maps.get('fabric_ports', {}).get(node_id, [])
                for port, neighbor, remote in fab_ports:
                    def render(parent, prefix, _port=port, _neighbor=neighbor, _remote=remote, _node_id=node_id):
                        data = {'type': 'port', 'node': _node_id, 'port': _port}
                        parent.add_leaf(f"{prefix}Port: [cyan]{_port}[/cyan] -> Neighbor: [bold green]{_neighbor}[/bold green] (Remote: {_remote})", data=data)
                    items.append({'port': port, 'render': render})
            
            # Mode: Service Ports
            elif self.port_view_mode == 'service':
                svc_ports = maps.get('service_ports', {}).get(node_id, [])
                for port, device in svc_ports:
                    def render(parent, prefix, _port=port, _device=device, _node_id=node_id):
                        data = {'type': 'port', 'node': _node_id, 'port': _port}
                        parent.add_leaf(f"{prefix}Port: [cyan]{_port}[/cyan] -> Service Device: [magenta]{_device}[/magenta]", data=data)
                    items.append({'port': port, 'render': render})

            # Mode: All (Default)
            elif self.port_view_mode == 'all':
                if node_id in port_map:
                    for port, vlans in port_map[node_id].items():
                        def render(parent, prefix, _port=port, _vlans=vlans, _node_id=node_id):
                            data = {'type': 'port', 'node': _node_id, 'port': _port}
                            is_expanded = has_state and (self._get_key(data) in expanded_nodes)
                            port_node = parent.add(f"{prefix}Port: [cyan]{_port}[/cyan]", data=data, expand=is_expanded)
                            data_to_node_map[self._get_key(data)] = port_node
                            
                            for vlan, epgs in sorted(_vlans.items()):
                                # Handle Neighbors
                                if vlan == '-neighbor':
                                    for item in epgs:
                                        port_node.add_leaf(f"Neighbor: [bold green]{item['name']}[/bold green] (Remote: {item.get('remote', 'N/A')})")
                                    continue

                                if vlan == 'untagged':
                                    target_node = port_node
                                else:
                                    target_node = port_node.add(f"VLAN: [yellow]{vlan}[/yellow]")
                                
                                for item in epgs:
                                    if item['type'] == 'EPG':
                                        target_node.add_leaf(f"EPG: {item['name']}")
                                    elif item['type'] == 'L3Out':
                                        target_node.add_leaf(f"L3Out: [bold blue]{item['name']}[/bold blue]")
                                    elif item['type'] == 'Service':
                                        target_node.add_leaf(f"Service Device: [magenta]{item['name']}[/magenta]")
                        items.append({'port': port, 'render': render})
            return items

        for node_obj in nodes:
            node_attr = node_obj['fabricNode']['attributes']
            node_id = node_attr['id']
            node_name = node_attr.get('name', 'Unknown')
            if node_id in processed_nodes:
                continue

            # Check visibility for current node
            show_node = True
            if relevant_nodes is not None and node_id not in relevant_nodes:
                show_node = False

            if node_id in vpc_pairs:
                peer_id = vpc_pairs[node_id]
                peer_name = node_id_to_name.get(peer_id, 'Unknown')
                
                # Check visibility for peer node
                show_peer = True
                if relevant_nodes is not None and peer_id not in relevant_nodes:
                    show_peer = False

                if not show_node and not show_peer:
                    processed_nodes.add(node_id)
                    processed_nodes.add(peer_id)
                    continue

                pair_data = f"vpc_pair_{node_id}_{peer_id}"
                pair_node = tree.root.add(f"[bold]vPC Pair: Node {node_id} ({node_name}) - Node {peer_id} ({peer_name})[/bold]", data=pair_data, expand=has_state and (self._get_key(pair_data) in expanded_nodes))
                data_to_node_map[pair_data] = pair_node
                processed_nodes.add(node_id)
                processed_nodes.add(peer_id)

                items1 = get_node_port_items(node_id) if show_node else []
                items2 = get_node_port_items(peer_id) if show_peer else []
                
                for i in items1: i['node_id'] = node_id
                for i in items2: i['node_id'] = peer_id
                
                all_items = items1 + items2
                all_items.sort(key=lambda x: (natural_sort_key(x['port']), x['node_id']))
                
                if all_items:
                    for item in all_items:
                        prefix = f"[dim][Node {item['node_id']}][/dim] "
                        item['render'](pair_node, prefix)
                else:
                    pair_node.add_leaf("[dim]No port assignments found[/dim]")
            else:
                if not show_node:
                    processed_nodes.add(node_id)
                    continue
                node_data = f"node_{node_id}"
                standalone_node = tree.root.add(f"[bold]Node: {node_id} ({node_name})[/bold]", data=node_data, expand=has_state and (self._get_key(node_data) in expanded_nodes))
                data_to_node_map[node_data] = standalone_node
                
                items = get_node_port_items(node_id)
                items.sort(key=lambda x: natural_sort_key(x['port']))
                
                if items:
                    for item in items:
                        item['render'](standalone_node, "")
                else:
                    standalone_node.add_leaf("[dim]No port assignments found[/dim]")
                processed_nodes.add(node_id)

        if cursor_data and cursor_data in data_to_node_map:
            tree.select_node(data_to_node_map[cursor_data])

        tree.focus()

    def action_refresh(self) -> None:
        """Refresh the tree view data."""
        now = time.time()
        if now - self.last_refresh_time < 5:
            self.notify("Please wait 5 seconds between refreshes.", title="Refresh Cooldown", severity="warning")
            return
        self.last_refresh_time = now
        self.save_state()

        classes = self.VIEW_CLASSES.get(self.current_view)
        self.run_worker(lambda: self.refresh_view_data(classes), thread=True)

    def refresh_view_data(self, classes):
        self.call_from_thread(lambda: setattr(self, 'sub_title', "Refreshing data..."))
        new_data = self.viewer._fetch_all_data(classes)
        self.data.update(new_data)
        self.maps = self.viewer._process_mappings(self.data)
        self.call_from_thread(self.build_tree)

    def action_search(self) -> None:
        if self.current_view == 'port':
            self.push_screen(PortSearchScreen(self))

    def set_port_view_mode(self, mode, epg=None):
        self.save_state()
        self.port_view_mode = mode
        self.selected_epg_for_view = epg
        self.build_tree()

    def on_tabs_tab_activated(self, event: Tabs.TabActivated) -> None:
        """Handle tab switching."""
        self.save_state()
        self.current_view = event.tab.id
        if event.tab.id == 'help':
            self.push_screen(WelcomeScreen(is_help_view=True))
            return

        # If data is not loaded yet, this will trigger the first load.
        # Otherwise, it will use cached data.
        self.build_tree()
        self.query_one(Tabs).focus() # Keep focus on tabs
        
    def action_quit(self) -> None:
        """Show the quit dialog."""
        self.push_screen(QuitScreen())
        
    def on_key(self, event: Key) -> None:
        """Handle key presses for the TUI."""
        # Prevent app-level key handling if a modal is active
        if isinstance(self.screen, ModalScreen):
            return

        tree = self.query_one("#tree", TextualTree)
        tabs = self.query_one(Tabs)

        if tabs.has_focus:
            if event.key == "right":
                current_idx = self.views.index(self.current_view)
                if current_idx < len(self.views) - 1:
                    next_view = self.views[current_idx + 1]
                    tabs.active = next_view
                event.prevent_default()
            elif event.key == "left":
                current_idx = self.views.index(self.current_view)
                if current_idx > 0:
                    prev_view = self.views[current_idx - 1]
                    tabs.active = prev_view
                event.prevent_default()

        elif tree.has_focus:
            if not tree.cursor_node:
                return
            
            node = tree.cursor_node

            if event.key == "right":
                if node.is_expanded:
                    # If already expanded, do nothing or move selection down (default behavior)
                    pass 
                else:
                    # Only perform recursive expand if not on the root node.
                    if node is not tree.root:
                        def expand_all(node_to_expand):
                            node_to_expand.expand()
                            for child in node_to_expand.children:
                                expand_all(child)
                        expand_all(node)
                event.prevent_default()
            
            elif event.key == "left":
                node.collapse()
                event.prevent_default()
            
            elif event.key == "space":
                node.toggle()
                event.prevent_default()
            
            elif event.key == "enter":
                if node.data and isinstance(node.data, dict) and node.data.get('type') == 'port':
                    node_id = node.data['node']
                    port_name = node.data['port']
                    attrs = self.maps.get('port_attributes', {}).get((node_id, port_name))
                    if attrs:
                        self.push_screen(PortDetailsScreen(attrs))
                    else:
                        self.push_screen(PortDetailsScreen({'Info': 'No detailed attributes found for this port.'}))

    def action_save_report(self) -> None:
        """Save the current tree view to a markdown file."""
        tree = self.query_one("#tree", TextualTree)
        
        # Map view IDs to readable names for filename
        view_names = {
            'network': 'Tenant_Network_View',
            'contract': 'Tenant_Contract_View',
            'global_contract': 'Contract_View',
            'port': 'Node_Port_View'
        }
        view_name = view_names.get(self.current_view, 'Unknown_View')
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{view_name}.({timestamp}).md"
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"# {view_name.replace('_', ' ')}\n\n")
                self._write_tree_node(f, tree.root, 0)
            
            self.notify(f"Report saved to {filename}", title="Success", severity="information")
        except Exception as e:
            self.notify(f"Failed to save report: {e}", title="Error", severity="error")

    def _write_tree_node(self, f, node, level):
        if level > 0:
            indent = "  " * (level - 1)
            label = node.label
            if hasattr(label, "plain"):
                text = label.plain
            else:
                text = str(label)
            f.write(f"{indent}- {text}\n")
        
        for child in node.children:
            self._write_tree_node(f, child, level + 1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ACI Tree Viewer")
    args = parser.parse_args()

    # Read configuration from config.ini
    config = configparser.ConfigParser()
    config_file = 'config.ini'
    if not config.read(config_file):
        print(f"[!] Error: Configuration file '{config_file}' not found or is empty.")
        print("[!] Please create it with an [ACI] section containing URL, USER, and PASSWORD.")
        exit()

    viewer = None
    try:
        aci_url = config.get('ACI', 'URL')
        aci_user = config.get('ACI', 'USER')
        aci_password = config.get('ACI', 'PASSWORD')
        viewer = AciTreeViewer(aci_url, aci_user, aci_password)
    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        print(f"[!] Error in configuration file: {e}")
        exit()

    viewer.visualize_tree()

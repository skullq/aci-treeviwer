import requests
import json
import urllib3
import re
import argparse
import configparser
from collections import defaultdict
from datetime import datetime
from rich.console import Console
from rich.tree import Tree
from rich.text import Text
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Tree as TextualTree, Static, Button, Label, Tabs, Tab
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
            health = int(health)
            color = "green" if health >= 90 else "yellow" if health >= 70 else "red"
            parts.append(f"[{color}]HS: {health}[/{color}]")
        if faults > 0:
            parts.append(f"[bold red]❗{faults}[/bold red]")
        return f" ({', '.join(parts)})" if parts else ""

    def _fetch_all_data(self, specific_classes=None):
        """모든 ACI 객체 데이터 수집"""
        all_classes = [
            'fvTenant', 'fvCtx', 'fvBD', 'fvAEPg', 'fvSubnet',
            'l3extOut', 'l3extInstP', 'l3extSubnet',
            'fvRsProv', 'fvRsCons', 'l3extRsProv', 'l3extRsCons',
            'vnsRsAbsGraphAtt', 'fvRsCtx', 'fvRsBd', 'l3extRsEctx',
            'vzAny', 'vzRsAnyToProv', 'vzRsAnyToCons', 'vzSubj', 'vzBrCP', 'ipRouteP', 'fabricNode', 'fabricVpcRT', 'fvRsPathAtt',
            'ipNexthopP', 'healthInst', 'faultInst', 'l3extRsPathL3OutAtt', 'lldpAdjEp', 'vnsRsCIfPathAtt'
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
        health_map = {h['healthInst']['attributes']['dn']: h['healthInst']['attributes']['cur'] for h in data.get('healthInst', []) if 'healthInst' in h}
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
        for rt in data.get('fabricVpcRT', []):
            if 'fabricVpcRT' in rt:
                dn = rt['fabricVpcRT']['attributes']['dn']
                match = re.search(r'rt-vpcp-.+-(\d+)-(\d+)', dn)
                if match:
                    node1, node2 = sorted([match.group(1), match.group(2)])
                    if node1 not in processed_vpc_nodes and node2 not in processed_vpc_nodes:
                        vpc_pairs[node1] = node2
                        processed_vpc_nodes.add(node1)
                        processed_vpc_nodes.add(node2)

        # 11. Port Mappings
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

        app_centric_map = defaultdict(lambda: {'prov': set(), 'cons': set()})
        contract_providers = defaultdict(set)
        dn_to_name = {t['fvTenant']['attributes']['dn']: t['fvTenant']['attributes']['name'] for t in data.get('fvTenant', []) if 'fvTenant' in t}
        
        epg_to_bd = {}
        for rs in data.get('fvRsBd', []):
            if 'fvRsBd' in rs:
                attr = rs['fvRsBd']['attributes']
                epg_dn = attr['dn'].replace('/rsbd', '')
                epg_to_bd[epg_dn] = attr['tDn']

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

                app_centric_map[(tenant_name, contract_name)]['prov'].add((epg_name, dn))
                contract_providers[(c_owner, contract_name)].add((tenant_name, epg_name, dn))
            for contract_name in conts['cons']:
                app_centric_map[(tenant_name, contract_name)]['cons'].add((epg_name, dn))

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
            'port_details_map': port_details_map
        }

    def visualize_tree(self, tenant_filter=None, display_mode='tree'):
        if display_mode == 'tui':
            app = AciTreeViewerApp(self, tenant_filter)
            app.run()
            return

        data = self._fetch_all_data()
        maps = self._process_mappings(data)
        console = Console()

        def get_cont_label(name, tenant_name):
            """Contract 이름에 방향성(Bi/Uni) 추가"""
            direction = maps['contract_info'].get((tenant_name, name))
            if not direction: direction = maps['contract_info'].get(('common', name), 'Bi')
            return f"{name} ({direction})"

        # Tree View Logic
        root = Tree("[bold blue]ACI Tree Viewer[/bold blue]")

        for t in data['fvTenant']:
            t_name, t_dn = t['fvTenant']['attributes']['name'], t['fvTenant']['attributes']['dn']
            if tenant_filter and t_name != tenant_filter:
                continue
            t_node = root.add(f"[bold]Tenant:[/bold] {t_name}{self._format_health_status(t_dn, maps['health_map'], maps['fault_map'])}")
            
            # Tenant별 VRF 필터링
            tenant_vrfs = [v for v in data['fvCtx'] if v['fvCtx']['attributes']['dn'].startswith(t_dn)]
            for v in tenant_vrfs:
                v_attr = v['fvCtx']['attributes'] 
                v_dn = v_attr['dn']
                v_name = v_attr['name']
                v_node = t_node.add(f"[bold]VRF:[/bold] {v_name} [dim](VNID: {v_attr.get('scope', 'N/A')}, pcTag: {self._format_tag(v_attr.get('pcTag', 'N/A'))})[/dim]{self._format_health_status(v_dn, maps['health_map'], maps['fault_map'])}")

                # vzAny (VRF Level Contracts)
                vzany_dn = f"{v_dn}/any"
                vz_conts = maps['total_conts'].get(vzany_dn)
                if vz_conts and (vz_conts['prov'] or vz_conts['cons']):
                    vz_node = v_node.add("[bold magenta]vzAny (VRF Contracts)[/bold magenta]")
                    for p in vz_conts['prov']:
                        vz_node.add(f"Provides: [cyan]{get_cont_label(p, t_name)}[/cyan]")
                    for c in vz_conts['cons']:
                        vz_node.add(f"Consumes: [cyan]{get_cont_label(c, t_name)}[/cyan]")

                # 내부망 섹션
                internal_node = v_node.add("[bold]Internal Network & Security[/bold]")
                t_bds = [b for b in data['fvBD'] if b['fvBD']['attributes']['dn'].startswith(t_dn) and maps['bd_to_vrf'].get(b['fvBD']['attributes']['dn']) == v_name]
                for b in t_bds:
                    bd_attr = b['fvBD']['attributes']
                    bd_name = bd_attr['name']
                    bd_node = internal_node.add(f"[bold]BD:[/bold] {bd_name} [dim](pcTag: {self._format_tag(bd_attr.get('pcTag', 'N/A'))})[/dim]{self._format_health_status(bd_attr['dn'], maps['health_map'], maps['fault_map'])}")
                    
                    # EPG 매핑
                    for rs in data['fvRsBd']:
                        rs_attr = rs['fvRsBd']['attributes']
                        if rs_attr['tnFvBDName'] == bd_name and rs_attr['dn'].startswith(t_dn):
                            epg_dn = rs_attr['dn'].replace('/rsbd', '')
                            epg_name = epg_dn.split('epg-')[-1]
                            epg_obj = next((e for e in data['fvAEPg'] if e['fvAEPg']['attributes']['dn'] == epg_dn), None)
                            pctag = self._format_tag(epg_obj['fvAEPg']['attributes'].get('pcTag', 'N/A')) if epg_obj else 'N/A'
                            
                            epg_node = bd_node.add(f"[bold]EPG:[/bold] {epg_name} [dim](pcTag: {pctag})[/dim]{self._format_health_status(epg_dn, maps['health_map'], maps['fault_map'])}")
                            conts = maps['total_conts'].get(epg_dn, {"prov": [], "cons": []})
                            for p in conts['prov']:
                                g = f" [bold red][Graph: {maps['cont_to_graph'][p]}][/bold red]" if p in maps['cont_to_graph'] else ""
                                epg_node.add(f"Provides: [cyan]{get_cont_label(p, t_name)}[/cyan]{g}")
                            for c in conts['cons']:
                                g = f" [bold red][Graph: {maps['cont_to_graph'][c]}][/bold red]" if c in maps['cont_to_graph'] else ""
                                epg_node.add(f"Consumes: [cyan]{get_cont_label(c, t_name)}[/cyan]{g}")

                # 외부망 섹션
                external_node = v_node.add("[bold]External Connectivity (L3Out)[/bold]")
                t_l3s = [l for l in data['l3extOut'] if l['l3extOut']['attributes']['dn'].startswith(t_dn) and maps['l3_to_vrf'].get(l['l3extOut']['attributes']['dn']) == v_name]
                for l in t_l3s:
                    l_dn = l['l3extOut']['attributes']['dn']
                    all_ads = list(set(maps['vrf_public_subnets'].get(v_name, []))) + maps['l3out_ext_info'].get(l_dn, [])
                    subnets_str = ", ".join(all_ads) if all_ads else "Private Only"
                    
                    l3_node = external_node.add(f"[bold]L3Out:[/bold] {l['l3extOut']['attributes']['name']}{self._format_health_status(l_dn, maps['health_map'], maps['fault_map'])}")
                    l3_node.add(f"Advertised: [green]{subnets_str}[/green]")
                    
                    # Static Routes
                    s_routes = maps['l3out_static_routes'].get(l_dn, [])
                    if s_routes:
                        sr_node = l3_node.add("[bold]Static Routes[/bold]")
                        nodes_routes = defaultdict(list)
                        for sr in s_routes:
                            nodes_routes[sr['node']].append(sr)
                        for node_id, routes in sorted(nodes_routes.items()):
                            node_branch = sr_node.add(f"[bold]Node {node_id}[/bold]")
                            for sr in sorted(routes, key=lambda x: x['prefix']):
                                nexthops = ", ".join(sorted(sr['nexthops']))
                                node_branch.add(f"[cyan]{sr['prefix']}[/cyan] via [yellow]{nexthops}[/yellow]")

                    # L3Out External EPG 및 Contract 매핑
                    for instp in data['l3extInstP']:
                        i_attr = instp['l3extInstP']['attributes']
                        if i_attr['dn'].startswith(l_dn):
                            i_dn = i_attr['dn']
                            ext_epg_node = l3_node.add(f"[bold]External EPG:[/bold] {i_attr['name']} [dim](pcTag: {self._format_tag(i_attr.get('pcTag', 'N/A'))})[/dim]{self._format_health_status(i_dn, maps['health_map'], maps['fault_map'])}")
                            
                            # Subnets under External EPG
                            for sub in maps['instp_subnets'].get(i_dn, []):
                                scope_str = self._format_scope(sub.get('scope', ''))
                                ext_epg_node.add(f"Subnet: [bold yellow]{sub['ip']}[/bold yellow] [dim](pcTag: {self._format_tag(sub.get('pcTag', 'N/A'))}, Scope: {scope_str})[/dim]")

                            i_conts = maps['total_conts'].get(i_dn, {"prov": [], "cons": []})
                            for p in i_conts['prov']:
                                g = f" [bold red][Graph: {maps['cont_to_graph'][p]}][/bold red]" if p in maps['cont_to_graph'] else ""
                                ext_epg_node.add(f"Provides: [cyan]{get_cont_label(p, t_name)}[/cyan]{g}")
                            for c in i_conts['cons']:
                                g = f" [bold red][Graph: {maps['cont_to_graph'][c]}][/bold red]" if c in maps['cont_to_graph'] else ""
                                ext_epg_node.add(f"Consumes: [cyan]{get_cont_label(c, t_name)}[/cyan]{g}")
        
        console.print(root)

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

    def on_status_update(self, message: StatusUpdate) -> None:
        self.update_status(message.message, message.color)

    def on_loading_complete(self, message: LoadingComplete) -> None:
        self.enable_start_button()

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
            self.app.pop_screen()

    def on_key(self, event: Key) -> None:
        if event.key == "y":
            self.app.exit()
        elif event.key == "n":
            self.app.pop_screen()

class AciTreeViewerApp(App):
    """A Textual app to view ACI topology."""

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("q", "quit", "Quit"),
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
    Tree {
        background: black;
        width: 100%;
        border: round white;
        scrollbar-color: white;
        scrollbar-background: black;
    }
    Tabs {
        dock: top;
    }
    WelcomeScreen {
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
            'fvTenant', 'fvAEPg', 'l3extInstP'
        ]
    }

    def __init__(self, viewer, tenant_filter):
        super().__init__()
        self.viewer = viewer
        self.tenant_filter = tenant_filter
        self.views = ['network', 'contract', 'port', 'help']
        self.current_view = 'network'
        self.data = {}
        self.maps = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield Tabs(
            Tab("Network", id="network"),
            Tab("Contract", id="contract"),
            Tab("Port", id="port"),
            Tab("Help", id="help"),
        )
        with Container(id="tree-pane"):
            yield TextualTree("ACI Topology", id="tree")
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
        view_map = {'network': 'Network', 'contract': 'Contract', 'port': 'Port'}
        
        if not self.data or not self.maps:
            self.sub_title = f"Loading {view_map.get(self.current_view, 'Unknown')} data..."
            return

        filter_status = ""
        if self.tenant_filter:
            filter_status = f" | Filter: {self.tenant_filter}"

        self.sub_title = f"View: {view_map.get(self.current_view, 'Unknown')}{filter_status} | Last updated: {datetime.now().strftime('%H:%M:%S')}"
        
        # Data is already loaded by load_initial_data or refresh
        # Just build the tree using cached data
        
        if self.current_view == 'network':
            self._build_network_tree()
        elif self.current_view == 'contract':
            self._build_contract_tree()
        elif self.current_view == 'port':
            self._build_port_tree()

    def _build_network_tree(self) -> None:
        """Fetches data and builds/refreshes the tree view, preserving state."""
        tree = self.query_one("#tree", TextualTree)

        # Preserve expansion and cursor state
        expanded_nodes = set()

        # The first build is when the tree root has no children yet.
        is_initial_build = not tree.root.children

        def _collect_expanded(node):
            if node.is_expanded and node.data:
                expanded_nodes.add(node.data)
            for child in node.children:
                _collect_expanded(child)
        
        _collect_expanded(tree.root)
        cursor_node = tree.cursor_node
        cursor_data = cursor_node.data if cursor_node else None
        parent_data = cursor_node.parent.data if cursor_node and cursor_node.parent else None

        tree.clear()
        tree.root.set_label("[bold blue]ACI Tree Viewer - Network View[/bold blue]")
        
        data = self.data
        maps = self.maps
        def get_cont_label(name, tenant_name):
            direction = maps['contract_info'].get((tenant_name, name))
            if not direction: direction = maps['contract_info'].get(('common', name), 'Bi')
            return f"{name} ({direction})"

        data_to_node_map = {}

        for t in data['fvTenant']:
            t_name, t_dn = t['fvTenant']['attributes']['name'], t['fvTenant']['attributes']['dn']
            if self.tenant_filter and t_name != self.tenant_filter:
                continue
            health_status = self.viewer._format_health_status(t_dn, maps['health_map'], maps['fault_map'])
            t_node = tree.root.add(
                f"[bold]Tenant:[/bold] {t_name}{health_status}",
                data=t_dn,
                expand=is_initial_build or t_dn in expanded_nodes
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
                    expand=v_dn in expanded_nodes
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
                        expand=vzany_node_dn in expanded_nodes
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
                    expand=internal_node_dn in expanded_nodes
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
                        expand=bd_dn in expanded_nodes
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
                                expand=epg_dn in expanded_nodes
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
                    expand=external_node_dn in expanded_nodes
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
                        expand=l_dn in expanded_nodes
                    )
                    data_to_node_map[l_dn] = l3_node
                    l3_node.add_leaf(f"Advertised: [green]{subnets_str}[/green]")
                    
                    s_routes = maps['l3out_static_routes'].get(l_dn, [])
                    if s_routes:
                        sr_node_dn = f"{l_dn}/static_routes"
                        sr_node = l3_node.add(
                            "[bold]Static Routes[/bold]",
                            data=sr_node_dn,
                            expand=sr_node_dn in expanded_nodes
                        )
                        data_to_node_map[sr_node_dn] = sr_node
                        
                        nodes_routes = defaultdict(list)
                        for sr in s_routes:
                            nodes_routes[sr['node']].append(sr)

                        for node_id, routes in sorted(nodes_routes.items()):
                            node_dn = f"{sr_node_dn}/node-{node_id}"
                            node_branch = sr_node.add(
                                f"[bold]Node {node_id}[/bold]",
                                data=node_dn,
                                expand=node_dn in expanded_nodes
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
                                expand=i_dn in expanded_nodes
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
        if cursor_data and cursor_data in data_to_node_map:
            tree.select_node(data_to_node_map[cursor_data])
        elif parent_data and parent_data in data_to_node_map:
            tree.select_node(data_to_node_map[parent_data])

        tree.focus()

    def _build_contract_tree(self) -> None:
        """Builds the contract-centric tree view."""
        tree = self.query_one("#tree", TextualTree)
        tree.clear()
        tree.root.set_label("[bold blue]ACI Tree Viewer - Contract View[/bold blue]")

        maps = self.maps
        app_map = maps['app_centric_map']
        health_map = maps['health_map']
        fault_map = maps['fault_map']
        epg_to_bd = maps['epg_to_bd']

        tenant_map = defaultdict(list)
        for (tenant, contract), epgs in app_map.items():
            tenant_map[tenant].append((contract, epgs))

        tenants_to_display = sorted(tenant_map.keys())
        if self.tenant_filter:
            tenants_to_display = [t for t in tenants_to_display if t == self.tenant_filter]

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
                expand=False
            )
            
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

                direction = maps['contract_info'].get((tenant, contract), 'Bi')
                
                contract_type = "Local Contract" if source_tenant == tenant else "Remote Contract"
                source_info = ""
                if source_tenant != tenant:
                    source_info = f", Source: [bold magenta]{source_tenant}[/bold magenta]"
                
                label = f"Contract: [cyan]{contract}[/cyan] ({direction}, {contract_type}, Scope: {scope}{source_info})"
                contract_dn = f"uni/tn-{source_tenant}/brc-{contract}"
                c_node = t_node.add(label, data=contract_dn)

                # Providers Section
                prov_node_dn = f"{contract_dn}/providers"
                all_provs = maps['contract_providers'].get((source_tenant, contract), set())
                prov_node = c_node.add(f"[green]Providers[/green] ({len(all_provs)})", data=prov_node_dn)
                
                if not all_provs:
                    prov_node.add_leaf("[dim]No Providers Configured[/dim]")
                else:
                    prov_groups = defaultdict(list)
                    for p_tenant, p_epg, p_dn in all_provs:
                        _, p_vrf = get_vrf_info(p_dn)
                        prov_groups[(p_tenant, p_vrf)].append((p_epg, p_dn))
                    
                    for (p_tenant, p_vrf), providers in sorted(prov_groups.items()):
                        loc_str = " [bold magenta](Local)[/bold magenta]" if p_tenant == tenant else ""
                        group_node = prov_node.add(f"[bold]Tenant:[/bold] {p_tenant}{loc_str} -> [bold]VRF:[/bold] {p_vrf}")
                        for epg_name, epg_dn in sorted(providers):
                            health_status = self.viewer._format_health_status(epg_dn, health_map, fault_map)
                            epg_node = group_node.add(f"EPG: {epg_name}{health_status}", data=epg_dn)
                            
                            net_info = get_network_info(epg_dn)
                            for info in net_info:
                                epg_node.add_leaf(f"Network: {info}")

                # Consumers Section (Grouped by Tenant -> VRF)
                cons_node_dn = f"{contract_dn}/consumers"
                cons_node = c_node.add(f"[yellow]Consumers[/yellow] ({len(epgs['cons'])})", data=cons_node_dn)
                if epgs['cons']:
                    # Group consumers by (Tenant, VRF)
                    cons_groups = defaultdict(list)
                    for epg_name, epg_dn in sorted(list(epgs['cons'])):
                        c_tenant, c_vrf = get_vrf_info(epg_dn)
                        cons_groups[(c_tenant, c_vrf)].append((epg_name, epg_dn))

                    for (c_tenant, c_vrf), consumers in sorted(cons_groups.items()):
                        group_node = cons_node.add(f"[bold]Tenant:[/bold] {c_tenant} -> [bold]VRF:[/bold] {c_vrf}")
                        for epg_name, epg_dn in consumers:
                            health_status = self.viewer._format_health_status(epg_dn, health_map, fault_map)
                            epg_node = group_node.add(f"EPG: {epg_name}{health_status}", data=epg_dn)
                            
                            # Network Info
                            net_info = get_network_info(epg_dn)
                            for info in net_info:
                                epg_node.add_leaf(f"Network: {info}")

                else: cons_node.add_leaf("[dim]None[/dim]")
        tree.focus()

    def _build_port_tree(self) -> None:
        """Builds the port-centric tree view."""
        tree = self.query_one("#tree", TextualTree)
        tree.clear()
        tree.root.set_label("[bold blue]ACI Tree Viewer - Port View[/bold blue]")

        maps = self.maps
        data = self.data
        port_map = maps.get('port_details_map', {})
        vpc_pairs = maps.get('vpc_pairs', {})
        
        nodes = sorted(data.get('fabricNode', []), key=lambda x: int(x['fabricNode']['attributes']['id']))
        node_id_to_name = {n['fabricNode']['attributes']['id']: n['fabricNode']['attributes']['name'] for n in nodes}

        if not nodes:
            tree.root.add_leaf("No fabric nodes found.")
            return

        processed_nodes = set()

        def natural_sort_key(s):
            return [int(text) if text.isdigit() else text.lower() for text in re.split(r'(\d+)', s)]

        def build_node_ports(parent_node, node_id):
            if node_id in port_map:
                for port, vlans in sorted(port_map[node_id].items(), key=lambda x: natural_sort_key(x[0])):
                    port_node = parent_node.add(f"Port: [cyan]{port}[/cyan]")
                    for vlan, epgs in sorted(vlans.items()):
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
            else:
                parent_node.add_leaf("[dim]No port assignments found[/dim]")

        for node_obj in nodes:
            node_attr = node_obj['fabricNode']['attributes']
            node_id = node_attr['id']
            node_name = node_attr.get('name', 'Unknown')
            if node_id in processed_nodes:
                continue

            if node_id in vpc_pairs:
                peer_id = vpc_pairs[node_id]
                peer_name = node_id_to_name.get(peer_id, 'Unknown')
                pair_node = tree.root.add(f"[bold]vPC Pair: Node {node_id} ({node_name}) - Node {peer_id} ({peer_name})[/bold]")
                processed_nodes.add(node_id)
                processed_nodes.add(peer_id)

                node1_branch = pair_node.add(f"Node {node_id} ({node_name})")
                build_node_ports(node1_branch, node_id)

                node2_branch = pair_node.add(f"Node {peer_id} ({peer_name})")
                build_node_ports(node2_branch, peer_id)
            else:
                standalone_node = tree.root.add(f"[bold]Node: {node_id} ({node_name})[/bold]")
                build_node_ports(standalone_node, node_id)
                processed_nodes.add(node_id)

        tree.focus()
        
    def action_refresh(self) -> None:
        """Refresh the tree view data."""
        classes = self.VIEW_CLASSES.get(self.current_view)
        self.run_worker(lambda: self.refresh_view_data(classes), thread=True)

    def refresh_view_data(self, classes):
        self.call_from_thread(lambda: setattr(self, 'sub_title', "Refreshing data..."))
        new_data = self.viewer._fetch_all_data(classes)
        self.data.update(new_data)
        self.maps = self.viewer._process_mappings(self.data)
        self.call_from_thread(self.build_tree)

    def on_tabs_tab_activated(self, event: Tabs.TabActivated) -> None:
        """Handle tab switching."""
        if event.tab.id == 'help':
            self.push_screen(WelcomeScreen(is_help_view=True))
            return

        self.current_view = event.tab.id
        # If data is not loaded yet, this will trigger the first load.
        # Otherwise, it will use cached data.
        self.build_tree()
        self.query_one(Tabs).focus() # Keep focus on tabs
        
    def action_quit(self) -> None:
        """Show the quit dialog."""
        self.push_screen(QuitScreen())
        
    def on_key(self, event: Key) -> None:
        """Handle key presses for the TUI."""
        tree = self.query_one("#tree", TextualTree)
        if not tree.has_focus:
            return

        if not tree.cursor_node:
            return
        
        node = tree.cursor_node

        if event.key == "right":
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ACI Tree Viewer")
    parser.add_argument("--tenant", help="Filter by Tenant name", default=None)
    parser.add_argument("--display", choices=['tree', 'tui'], default='tree', help="Output format: tree (default) or tui (interactive)")
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

    viewer = AciTreeViewer(aci_url, aci_user, aci_password)
    viewer.visualize_tree(tenant_filter=args.tenant, display_mode=args.display)

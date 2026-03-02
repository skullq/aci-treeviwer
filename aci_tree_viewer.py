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
from textual.widgets import Header, Footer, Tree as TextualTree, Static, Button, Label
from textual.containers import Container, ScrollableContainer, Vertical
from textual.events import Key
from rich.panel import Panel
from textual.screen import ModalScreen


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

    def _fetch_all_data(self):
        """모든 ACI 객체 데이터 수집"""
        classes = [
            'fvTenant', 'fvCtx', 'fvBD', 'fvAEPg', 'fvSubnet',
            'l3extOut', 'l3extInstP', 'l3extSubnet',
            'fvRsProv', 'fvRsCons', 'l3extRsProv', 'l3extRsCons',
            'vnsRsAbsGraphAtt', 'fvRsCtx', 'fvRsBd', 'l3extRsEctx',
            'vzAny', 'vzRsAnyToProv', 'vzRsAnyToCons', 'vzSubj', 'ipRouteP',
            'ipNexthopP', 'healthInst', 'faultInst'
        ]
        return {cls: self.get_data(cls) for cls in classes}

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

        # 4. Subnet 및 광고 정보
        vrf_public_subnets = defaultdict(list)
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
        
        app_centric_map = defaultdict(lambda: {'prov': set(), 'cons': set()})
        dn_to_name = {t['fvTenant']['attributes']['dn']: t['fvTenant']['attributes']['name'] for t in data.get('fvTenant', []) if 'fvTenant' in t}
        for epg in data.get('fvAEPg', []):
            if 'fvAEPg' in epg:
                dn_to_name[epg['fvAEPg']['attributes']['dn']] = epg['fvAEPg']['attributes']['name']
        for epg in data.get('l3extInstP', []):
            if 'l3extInstP' in epg:
                dn_to_name[epg['l3extInstP']['attributes']['dn']] = epg['l3extInstP']['attributes']['name']
        for dn, conts in total_conts.items():
            if not ('/epg-' in dn or '/instP-' in dn): continue
            tenant_match = re.match(r'uni/tn-([^/]+)', dn)
            if not tenant_match: continue
            tenant_name = tenant_match.group(1)
            epg_name = dn_to_name.get(dn, dn.split('/')[-1])
            for contract_name in conts['prov']:
                app_centric_map[(tenant_name, contract_name)]['prov'].add((epg_name, dn))
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
            'instp_subnets': instp_subnets, 'l3out_static_routes': l3out_static_routes,
            'health_map': health_map, 'fault_map': fault_map, 'app_centric_map': app_centric_map,
            'dn_to_full_obj': dn_to_full_obj
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
        ("v", "toggle_view", "Toggle View"),
        ("q", "quit", "Quit"),
    ]

    TITLE = "ACI Tree Viewer"
    CSS = """
    Screen {
        layout: vertical;
    }
    #main-container {
        layout: horizontal;
        height: 1fr;
    }
    Tree {
        background: $panel;
        width: 60%;
        border: round white;
    }
    #details-pane {
        padding: 0 1;
        width: 40%;
    }
    QuitScreen {
        align: center middle;
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

    def __init__(self, viewer, tenant_filter):
        super().__init__()
        self.viewer = viewer
        self.tenant_filter = tenant_filter
        self.views = ['network', 'application']
        self.current_view = 'network'
        self.data = {}
        self.maps = {}

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="main-container"):
            yield TextualTree("ACI Topology", id="tree")
            yield Static("Select an object to see details.", id="details-pane")
        yield Footer()

    def on_mount(self) -> None:
        """Called when app starts, builds the tree."""
        self.build_tree()

    def build_tree(self) -> None:
        """Fetches data and dispatches to the correct tree builder."""
        view_map = {'network': 'Network', 'application': 'App'}
        filter_status = ""
        if self.tenant_filter:
            filter_status = f" | Filter: {self.tenant_filter}"

        self.sub_title = f"View: {view_map.get(self.current_view, 'Unknown')}{filter_status} | Last updated: {datetime.now().strftime('%H:%M:%S')}"
        
        self.data = self.viewer._fetch_all_data()
        self.maps = self.viewer._process_mappings(self.data)

        if self.current_view == 'network':
            self._build_network_tree()
        elif self.current_view == 'application':
            self._build_app_tree()

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

    def _build_app_tree(self) -> None:
        """Builds the application-centric tree view."""
        tree = self.query_one("#tree", TextualTree)
        tree.clear()
        tree.root.set_label("[bold blue]ACI Tree Viewer - App View[/bold blue]")

        maps = self.maps
        app_map = maps['app_centric_map']
        health_map = maps['health_map']
        fault_map = maps['fault_map']

        tenant_map = defaultdict(list)
        for (tenant, contract), epgs in app_map.items():
            tenant_map[tenant].append((contract, epgs))

        tenants_to_display = sorted(tenant_map.keys())
        if self.tenant_filter:
            tenants_to_display = [t for t in tenants_to_display if t == self.tenant_filter]

        for tenant in tenants_to_display:
            t_dn = f"uni/tn-{tenant}"
            health_status = self.viewer._format_health_status(t_dn, health_map, fault_map)
            t_node = tree.root.add(f"[bold]Tenant:[/bold] {tenant}{health_status}")
            contracts = sorted(tenant_map[tenant], key=lambda x: x[0])
            if not contracts: t_node.add_leaf("No contract relationships found.")

            for contract, epgs in contracts:
                direction = maps['contract_info'].get((tenant, contract), 'Bi')
                contract_dn = f"uni/tn-{tenant}/brc-{contract}"
                c_node = t_node.add(f"Contract: [cyan]{contract}[/cyan] ({direction})", data=contract_dn)
                
                prov_node_dn = f"{contract_dn}/providers"
                prov_node = c_node.add(f"[green]Providers[/green] ({len(epgs['prov'])})", data=prov_node_dn)
                if epgs['prov']:
                    for epg_name, epg_dn in sorted(list(epgs['prov'])):
                        health_status = self.viewer._format_health_status(epg_dn, health_map, fault_map)
                        prov_node.add_leaf(f"EPG: {epg_name}{health_status}", data=epg_dn)
                else: prov_node.add_leaf("[dim]None[/dim]")

                cons_node_dn = f"{contract_dn}/consumers"
                cons_node = c_node.add(f"[yellow]Consumers[/yellow] ({len(epgs['cons'])})", data=cons_node_dn)
                if epgs['cons']:
                    for epg_name, epg_dn in sorted(list(epgs['cons'])):
                        health_status = self.viewer._format_health_status(epg_dn, health_map, fault_map)
                        cons_node.add_leaf(f"EPG: {epg_name}{health_status}", data=epg_dn)
                else: cons_node.add_leaf("[dim]None[/dim]")
        tree.focus()
        
    def action_refresh(self) -> None:
        """Refresh the tree view data."""
        self.build_tree()

    def action_toggle_view(self) -> None:
        """Toggle between network and application-centric views."""
        self.current_view = 'application' if self.current_view == 'network' else 'network'
        self.build_tree()
        
    def action_quit(self) -> None:
        """Show the quit dialog."""
        self.push_screen(QuitScreen())
        
    def on_key(self, event: Key) -> None:
        """Handle key presses for the TUI."""
        tree = self.query_one("#tree", TextualTree)
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

        elif event.key == "enter":
            details_pane = self.query_one("#details-pane", Static)
            node_data = node.data

            if not node_data:
                details_pane.update("Select an object to see details.")
                return

            dn_to_full_obj = self.maps.get('dn_to_full_obj', {})
            obj_details = dn_to_full_obj.get(node_data)

            if obj_details:
                api_request_info = f"[bold green]GET[/bold green] /api/mo/{node_data}.json"
                formatted_details = [api_request_info, ""]
                for key, value in sorted(obj_details.items()):
                    formatted_details.append(f"[bold cyan]{key}:[/bold cyan] {value}")
                details_pane.update("\n".join(formatted_details))
            else:
                details_pane.update(f"No detailed attributes for this item.\n\nDN: {node_data}")
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

    try:
        aci_url = config.get('ACI', 'URL')
        aci_user = config.get('ACI', 'USER')
        aci_password = config.get('ACI', 'PASSWORD')
    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        print(f"[!] Error in configuration file: {e}")
        exit()

    viewer = AciTreeViewer(aci_url, aci_user, aci_password)
    viewer.visualize_tree(tenant_filter=args.tenant, display_mode=args.display)

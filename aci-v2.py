import requests
import json
import urllib3
import re
import argparse
from collections import defaultdict
from rich.console import Console
from rich.tree import Tree

# SSL 인증서 경고 무시
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ACIFullAuditVisualizer:
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

    def _fetch_all_data(self):
        """모든 ACI 객체 데이터 수집"""
        classes = [
            'fvTenant', 'fvCtx', 'fvBD', 'fvAEPg', 'fvSubnet',
            'l3extOut', 'l3extInstP', 'l3extSubnet',
            'fvRsProv', 'fvRsCons', 'l3extRsProv', 'l3extRsCons',
            'vnsRsAbsGraphAtt', 'fvRsCtx', 'fvRsBd', 'l3extRsEctx',
            'vzAny', 'vzRsAnyToProv', 'vzRsAnyToCons', 'vzSubj'
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
        for s in data['fvSubnet']:
            attr = s['fvSubnet']['attributes']
            if 'public' in attr.get('scope', ''):
                bd_dn = attr['dn'].split('/subnet-')[0]
                v_name = bd_to_vrf.get(bd_dn)
                if v_name: vrf_public_subnets[v_name].append(attr['ip'])

        l3out_ext_info = defaultdict(list)
        for ls in data['l3extSubnet']:
            attr = ls['l3extSubnet']['attributes']
            ip, pctag = attr.get('ip', ''), attr.get('pcTag')
            if not pctag or pctag in ['0', 'unspecified']: pctag = '15' if ip == '0.0.0.0/0' else 'N/A'
            match = re.match(r'(uni/tn-[^/]+/out-[^/]+)', attr['dn'])
            if match and (ip == '0.0.0.0/0' or pctag == '15'):
                l3out_ext_info[match.group(1)].append(f"0.0.0.0/0 (pcTag:{self._format_tag(pctag)})")

        # 5. Contract Direction (vzSubj)
        contract_info = {}
        for subj in data.get('vzSubj', []):
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
        for sub in data['l3extSubnet']:
            attr = sub['l3extSubnet']['attributes']
            match = re.match(r'(.+/instP-[^/]+)/extsubnet-.+', attr['dn'])
            if match:
                instp_subnets[match.group(1)].append(attr)

        return {
            'bd_to_vrf': bd_to_vrf,
            'l3_to_vrf': l3_to_vrf,
            'cont_to_graph': cont_to_graph,
            'total_conts': total_conts,
            'vrf_public_subnets': vrf_public_subnets,
            'l3out_ext_info': l3out_ext_info,
            'contract_info': contract_info,
            'instp_subnets': instp_subnets
        }

    def visualize_tree(self, tenant_filter=None):
        data = self._fetch_all_data()
        maps = self._process_mappings(data)
        console = Console()
        
        root = Tree("[bold blue]ACI Audit Topology Report[/bold blue] (with Service Graph & pcTag)")

        def get_cont_label(name, tenant_name):
            """Contract 이름에 방향성(Bi/Uni) 추가"""
            direction = maps['contract_info'].get((tenant_name, name))
            if not direction: direction = maps['contract_info'].get(('common', name), 'Bi')
            return f"{name} ({direction})"

        for t in data['fvTenant']:
            t_name, t_dn = t['fvTenant']['attributes']['name'], t['fvTenant']['attributes']['dn']
            if tenant_filter and t_name != tenant_filter:
                continue
            t_node = root.add(f"[bold]Tenant:[/bold] {t_name}")
            
            # Tenant별 VRF 필터링
            tenant_vrfs = [v for v in data['fvCtx'] if v['fvCtx']['attributes']['dn'].startswith(t_dn)]
            for v in tenant_vrfs:
                v_attr = v['fvCtx']['attributes'] 
                v_dn = v_attr['dn']
                v_name = v_attr['name']
                v_node = t_node.add(f"[bold]VRF:[/bold] {v_name} [dim](VNID: {v_attr.get('scope', 'N/A')}, pcTag: {self._format_tag(v_attr.get('pcTag', 'N/A'))})[/dim]")

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
                    bd_node = internal_node.add(f"[bold]BD:[/bold] {bd_name} [dim](pcTag: {self._format_tag(bd_attr.get('pcTag', 'N/A'))})[/dim]")
                    
                    # EPG 매핑
                    for rs in data['fvRsBd']:
                        rs_attr = rs['fvRsBd']['attributes']
                        if rs_attr['tnFvBDName'] == bd_name and rs_attr['dn'].startswith(t_dn):
                            epg_dn = rs_attr['dn'].replace('/rsbd', '')
                            epg_name = epg_dn.split('epg-')[-1]
                            epg_obj = next((e for e in data['fvAEPg'] if e['fvAEPg']['attributes']['dn'] == epg_dn), None)
                            pctag = self._format_tag(epg_obj['fvAEPg']['attributes'].get('pcTag', 'N/A')) if epg_obj else 'N/A'
                            
                            epg_node = bd_node.add(f"[bold]EPG:[/bold] {epg_name} [dim](pcTag: {pctag})[/dim]")
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
                    
                    l3_node = external_node.add(f"[bold]L3Out:[/bold] {l['l3extOut']['attributes']['name']}")
                    l3_node.add(f"Advertised: [green]{subnets_str}[/green]")
                    
                    # L3Out External EPG 및 Contract 매핑
                    for instp in data['l3extInstP']:
                        i_attr = instp['l3extInstP']['attributes']
                        if i_attr['dn'].startswith(l_dn):
                            i_dn = i_attr['dn']
                            ext_epg_node = l3_node.add(f"[bold]External EPG:[/bold] {i_attr['name']} [dim](pcTag: {self._format_tag(i_attr.get('pcTag', 'N/A'))})[/dim]")
                            
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ACI Audit Visualizer")
    parser.add_argument("--tenant", help="Filter by Tenant name", default=None)
    args = parser.parse_args()

    visualizer = ACIFullAuditVisualizer("https://192.168.200.131", "admin", "p@ssw0rd")
    visualizer.visualize_tree(tenant_filter=args.tenant)

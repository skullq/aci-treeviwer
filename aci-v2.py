import requests
import json
import urllib3
import re
from collections import defaultdict

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

    def _fetch_all_data(self):
        """모든 ACI 객체 데이터 수집"""
        classes = [
            'fvTenant', 'fvCtx', 'fvBD', 'fvAEPg', 'fvSubnet',
            'l3extOut', 'l3extInstP', 'l3extSubnet',
            'fvRsProv', 'fvRsCons', 'l3extRsProv', 'l3extRsCons',
            'vnsRsAbsGraphAtt', 'fvRsCtx', 'fvRsBd', 'l3extRsEctx'
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

        return {
            'bd_to_vrf': bd_to_vrf,
            'l3_to_vrf': l3_to_vrf,
            'cont_to_graph': cont_to_graph,
            'total_conts': total_conts,
            'vrf_public_subnets': vrf_public_subnets,
            'l3out_ext_info': l3out_ext_info
        }

    def build_markdown_tree(self):
        data = self._fetch_all_data()
        maps = self._process_mappings(data)
        
        md = "# ACI Audit Topology Report (with Service Graph & pcTag)\n\n"
        for t in data['fvTenant']:
            t_name, t_dn = t['fvTenant']['attributes']['name'], t['fvTenant']['attributes']['dn']
            md += f"## 🏢 Tenant: {t_name}\n"
            
            # Tenant별 VRF 필터링
            tenant_vrfs = [v for v in data['fvCtx'] if v['fvCtx']['attributes']['dn'].startswith(t_dn)]
            for v in tenant_vrfs:
                v_attr = v['fvCtx']['attributes']
                v_name = v_attr['name']
                md += f"  ### 🛣️ VRF: {v_name} `(VNID: {v_attr.get('scope', 'N/A')}, pcTag: {self._format_tag(v_attr.get('pcTag', 'N/A'))})`\n"

                # 내부망 섹션
                md += "    #### 🟦 Internal Network & Security\n"
                t_bds = [b for b in data['fvBD'] if b['fvBD']['attributes']['dn'].startswith(t_dn) and maps['bd_to_vrf'].get(b['fvBD']['attributes']['dn']) == v_name]
                for b in t_bds:
                    bd_attr = b['fvBD']['attributes']
                    bd_name = bd_attr['name']
                    md += f"      * **BD:** {bd_name} `(pcTag: {self._format_tag(bd_attr.get('pcTag', 'N/A'))})`\n"
                    
                    # EPG 매핑
                    for rs in data['fvRsBd']:
                        rs_attr = rs['fvRsBd']['attributes']
                        if rs_attr['tnFvBDName'] == bd_name and rs_attr['dn'].startswith(t_dn):
                            epg_dn = rs_attr['dn'].replace('/rsbd', '')
                            epg_name = epg_dn.split('epg-')[-1]
                            epg_obj = next((e for e in data['fvAEPg'] if e['fvAEPg']['attributes']['dn'] == epg_dn), None)
                            pctag = self._format_tag(epg_obj['fvAEPg']['attributes'].get('pcTag', 'N/A')) if epg_obj else 'N/A'
                            
                            md += f"        * 🔗 **EPG:** {epg_name} `(pcTag: {pctag})`\n"
                            conts = maps['total_conts'].get(epg_dn, {"prov": [], "cons": []})
                            for p in conts['prov']:
                                g = f" [🔥 Graph: {maps['cont_to_graph'][p]}]" if p in maps['cont_to_graph'] else ""
                                md += f"          * 📤 **Provides:** `{p}`{g}\n"
                            for c in conts['cons']:
                                g = f" [🔥 Graph: {maps['cont_to_graph'][c]}]" if c in maps['cont_to_graph'] else ""
                                md += f"          * 📥 **Consumes:** `{c}`{g}\n"

                # 외부망 섹션
                md += "    #### 🌍 External Connectivity (L3Out)\n"
                t_l3s = [l for l in data['l3extOut'] if l['l3extOut']['attributes']['dn'].startswith(t_dn) and maps['l3_to_vrf'].get(l['l3extOut']['attributes']['dn']) == v_name]
                for l in t_l3s:
                    l_dn = l['l3extOut']['attributes']['dn']
                    all_ads = list(set(maps['vrf_public_subnets'].get(v_name, []))) + maps['l3out_ext_info'].get(l_dn, [])
                    subnets_str = ", ".join(all_ads) if all_ads else "Private Only"
                    md += f"      * **L3Out:** {l['l3extOut']['attributes']['name']}\n"
                    md += f"        * 📢 **Advertised:** `[ {subnets_str} ]`\n"
                    
                    # L3Out External EPG 및 Contract 매핑
                    for instp in data['l3extInstP']:
                        i_attr = instp['l3extInstP']['attributes']
                        if i_attr['dn'].startswith(l_dn):
                            i_dn = i_attr['dn']
                            md += f"        * 🌐 **External EPG:** {i_attr['name']} `(pcTag: {self._format_tag(i_attr.get('pcTag', 'N/A'))})`\n"
                            i_conts = maps['total_conts'].get(i_dn, {"prov": [], "cons": []})
                            for p in i_conts['prov']:
                                g = f" [🔥 Graph: {maps['cont_to_graph'][p]}]" if p in maps['cont_to_graph'] else ""
                                md += f"          * 📤 **Provides:** `{p}`{g}\n"
                            for c in i_conts['cons']:
                                g = f" [🔥 Graph: {maps['cont_to_graph'][c]}]" if c in maps['cont_to_graph'] else ""
                                md += f"          * 📥 **Consumes:** `{c}`{g}\n"
            md += "\n---\n"
        return md

if __name__ == "__main__":
    visualizer = ACIFullAuditVisualizer("https://192.168.200.131", "admin", "Cisco123!@#")
    print(visualizer.build_markdown_tree())
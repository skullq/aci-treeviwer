이 코드는 **Cisco ACI (Application Centric Infrastructure)** 환경의 구성 요소와 논리적 관계를 시각화해주는 Python 스크립트입니다. `Rich` 라이브러리를 사용하여 깔끔한 콘솔 출력을 제공하며, `Textual` 프레임워크를 통해 대화형 TUI(Text User Interface) 환경도 지원합니다.

주요 기능과 특징은 다음과 같습니다:

### 1. 데이터 수집 및 처리
*   **ACI 연동**: `config.ini` 파일의 설정 정보를 이용해 APIC에 로그인하고 세션을 맺습니다.
*   **객체 정보 조회**: REST API를 통해 Tenant, VRF, Bridge Domain(BD), EPG, Contract, L3Out, Subnet, Static Route, Health Score, Fault 등 방대한 ACI 객체 정보를 수집합니다.
*   **관계 매핑**: 수집된 데이터를 바탕으로 객체 간의 연결 관계(예: BD-VRF, Contract-EPG, L3Out-Node 등)를 분석하고 구조화합니다.

### 2. 시각화 모드 (Display Modes)
사용자는 실행 인자(`--display`)를 통해 두 가지 모드 중 하나를 선택할 수 있습니다.
*   **Tree 모드 (기본값)**: 콘솔에 정적인 트리 구조로 전체 토폴로지를 출력합니다.
*   **TUI 모드 (`tui`)**: 키보드로 탐색하고 상호작용할 수 있는 대화형 인터페이스를 실행합니다.

### 3. 제공하는 뷰 (Views)
스크립트는 두 가지 관점의 뷰를 제공하며, TUI 모드에서는 `v` 키를 눌러 전환할 수 있습니다.

*   **Network View (네트워크 관점)**
    *   물리적/논리적 네트워크 계층 구조를 시각화합니다.
    *   **구조**: Tenant → VRF → (vzAny / Internal / External)
    *   **Internal**: BD → EPG → Contract (Provides/Consumes)
    *   **External**: L3Out → Node Profile (Node, Static Route) → External EPG → Contract
    *   각 객체의 Health Score와 Fault 상태를 함께 표시합니다.

*   **Contract View (애플리케이션/정책 관점)**
    *   Contract를 중심으로 어떤 EPG들이 연결되어 있는지 보여줍니다.
    *   **구조**: Tenant → Contract → Provider EPG / Consumer EPG
    *   **특징**:
        *   Consumer EPG들은 Tenant 및 VRF별로 그룹화하여 보여줍니다.
        *   다른 Tenant에 있는 Provider 정보도 식별하여 표시합니다.
        *   EPG나 L3Out과 연관된 네트워크 정보(Subnet, Static Route, BD 정보)를 함께 제공하여 라우팅 관점의 가시성을 높였습니다.

### 4. 기타 편의 기능
*   **필터링**: `--tenant` 옵션을 통해 특정 Tenant의 정보만 조회할 수 있습니다.
*   **상세 정보 조회**: TUI 모드에서 노드를 선택(Enter)하면 해당 객체의 상세 속성(API 경로 및 속성값)을 우측 패널에서 확인할 수 있습니다.
*   **상태 모니터링**: 각 구성 요소 옆에 Health Score(색상으로 상태 구분)와 Fault 개수를 표시하여 현재 상태를 직관적으로 파악할 수 있습니다.
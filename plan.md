# ACI Tree Viewer: 기능 명세 및 개발 계획

## 1. 개요 (Overview)

`ACI Tree Viewer`는 Cisco ACI(Application Centric Infrastructure) 패브릭의 복잡한 객체 관계를 시각적으로 표현하여 네트워크 구성의 이해를 돕는 도구입니다. Tenant, VRF, BD, EPG, L3Out, Contract 등 주요 객체 간의 논리적 연결성을 직관적인 트리 형태로 제공합니다.

CLI 기반의 정적 트리 뷰와 TUI(Textual User Interface) 기반의 동적 뷰를 모두 지원하여, 사용자가 원하는 방식으로 ACI 구성을 탐색하고 분석할 수 있도록 돕습니다.

## 2. 주요 기능 (Key Features)

### 2.1. 데이터 수집 및 처리
- **실시간 데이터 수집**: ACI APIC REST API를 통해 실시간으로 객체 정보를 수집합니다.
- **안전한 접속**: `config.ini` 파일을 이용해 APIC 접속 정보(URL, 사용자, 암호)를 코드와 분리하여 안전하게 관리합니다.
- **포괄적인 정보 수집**: Tenant, VRF, BD, EPG, L3Out, Contract, Health Score, Fault 등 다수의 핵심 ACI 클래스 정보를 수집합니다.
- **관계 매핑**: 수집된 데이터를 기반으로 객체 간의 복잡한 관계(VRF-BD, BD-EPG, EPG-Contract 등)를 자동으로 매핑하고 분석합니다.
- **상세 정보 가공**: Contract의 방향성(Bi/Uni-directional), Service Graph 연동 여부, L3Out을 통해 광고되는 Subnet 정보 등을 가공하여 표시합니다.

### 2.2. 시각화 (Visualization)

#### 네트워크 중심 뷰 (Network-Centric View)
- `Tenant > VRF > (내부망/외부망)`의 계층적 구조로 전통적인 네트워크 토폴로지를 표현합니다.
- **내부망**: `BD > EPG` 구조로 표시하며, EPG에 연결된 Contract(Provided/Consumed) 정보를 함께 보여줍니다.
- **외부망**: `L3Out > External EPG` 구조로 표시하며, 광고되는 Subnet, Static Route, External EPG에 연결된 Contract 정보를 표시합니다.
- **상태 정보**: 각 객체의 Health Score 및 Fault 개수를 시각적으로 표시하여 직관적인 상태 파악을 지원합니다.

#### 애플리케이션 중심 뷰 (Application-Centric View - TUI 전용)
- `Tenant > Contract > (Providers/Consumers)`의 계층적 구조로 애플리케이션 정책 중심의 관계를 표현합니다.
- 특정 Contract를 어떤 EPG들이 Provide/Consume하는지 쉽게 파악할 수 있습니다.

### 2.3. 사용자 인터페이스 (User Interface)

- **정적 트리 뷰 (`--display tree`)**:
  - `rich` 라이브러리를 사용하여 터미널에 전체 구성 트리를 한번에 출력합니다.
  - `--tenant` 인자를 통해 특정 Tenant 정보만 필터링하여 볼 수 있습니다.

- **동적 TUI 뷰 (`--display tui`)**:
  - `textual` 라이브러리를 기반으로 한 인터랙티브 TUI를 제공합니다.
  - **(Enter)**: 선택된 객체의 상세 속성(DN, API 경로, 속성값 등)을 별도 패널에 표시합니다.
  - **(r)**: APIC으로부터 데이터를 다시 가져와 화면을 실시간으로 갱신합니다.
  - **(v)**: 네트워크 중심 뷰와 애플리케이션 중심 뷰를 상호 전환합니다.
  - **(q)**: 종료 확인 창을 띄운 후 애플리케이션을 종료합니다.
  - **(→)**: 선택된 노드와 그 아래의 모든 하위 노드를 펼칩니다.
  - 키보드 방향키로 트리 구조를 편리하게 탐색할 수 있습니다.

## 3. 향후 개발 방향 (Future Development Plan)

### 3.1. 단기 목표 (Short-term)

- **성능 개선**:
  - 데이터 로딩 시간 단축을 위한 API 요청 병렬 처리 도입을 검토합니다.
  - 반복적인 데이터 요청을 줄이기 위한 로컬 캐싱 기능 도입을 고려합니다.
- **TUI 기능 강화**:
  - 트리 내에서 특정 객체(예: EPG 이름, IP 주소)를 검색하는 기능을 추가합니다.
  - 상세 정보 패널에 연관 객체(예: Contract의 Provider EPG)로 바로 이동할 수 있는 하이퍼링크 기능을 추가합니다.
  - 현재 보고 있는 뷰를 텍스트 파일로 저장하는 기능을 구현합니다.
- **코드 리팩토링**:
  - 데이터 처리 로직과 시각화 로직의 의존성을 줄여 코드의 모듈성을 강화합니다.
  - 클래스 및 함수를 재구성하여 가독성 및 유지보수성을 향상시킵니다.

### 3.2. 중기 목표 (Mid-term)

- **다양한 뷰 추가**:
  - 물리적 토폴로지 뷰 (Spine-Leaf-Interface-EPG)를 추가하여 물리적 연결성 파악을 돕습니다.
  - Fault 중심 뷰 (전체 Fault 목록을 보고 해당 장애 객체로 바로 이동)를 구현합니다.
- **객체 상세 정보 확장**:
  - Contract 선택 시 Filter Entry 상세 정보를 표시합니다.
  - EPG 선택 시 학습된 Endpoint(IP, MAC) 정보를 표시하는 기능을 추가합니다.
- **설정 변경 추적**:
  - 특정 시점의 스냅샷을 저장하고, 현재 상태와 비교하여 변경된 부분을 하이라이팅하는 기능을 개발합니다.

### 3.3. 장기 목표 (Long-term)

- **Web 기반 인터페이스**:
  - 다수 사용자가 브라우저를 통해 쉽게 접근하고 결과를 공유할 수 있는 웹 기반 뷰어를 개발합니다.
- **제한적인 쓰기(Write) 기능**:
  - 객체에 Description을 추가/수정하는 등 위험도가 낮은 간단한 설정 변경 기능을 도입합니다 (별도 권한 및 경고 메시지 필수).
- **외부 시스템 연동**:
  - Prometheus와 연동하여 시계열 메트릭을 시각화하거나, 장애 발생 시 Jira 등 티켓 시스템과 연동하는 기능을 구상합니다.
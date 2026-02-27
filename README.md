# ACI Tree Viewer

A powerful command-line tool to visualize Cisco ACI fabric configurations in a hierarchical tree structure. It provides both static and interactive TUI (Text User Interface) modes for intuitive browsing and analysis of your ACI environment.

## Key Features

*   **Multiple Display Modes**:
    *   **`tree` (default)**: A static, color-coded tree view of the entire ACI configuration, perfect for quick overviews and generating reports.
    *   **`tui` (interactive)**: A full-featured, interactive terminal application for in-depth, real-time analysis.

*   **Interactive TUI Mode (`--display tui`)**:
    *   **Dual-View System**:
        *   **Network-Centric View**: The traditional hierarchy (`Tenant` -> `VRF` -> `BD` -> `EPG`).
        *   **Application-Centric View**: A view centered around contracts, showing provider/consumer EPG relationships (`Tenant` -> `Contract` -> `Providers/Consumers`).
        *   Toggle between views instantly with the `v` key.
    *   **Real-time Health Monitoring**:
        *   Displays the **Health Score (HS)** and **Fault Count (❗)** for each object directly in the tree, allowing for immediate identification of issues.
    *   **Detailed Object Inspector**:
        *   Select any object in the tree and press `Enter` to view its complete set of attributes in a dedicated details pane.
    *   **API Request Visibility**:
        *   The details pane also shows the corresponding REST API `GET` request used to fetch the object's data, aiding in automation and learning.
    *   **On-demand Refresh**:
        *   Press the `r` key at any time to fetch the latest data from the APIC and refresh the display.

*   **Secure External Configuration**:
    *   APIC connection details (URL, username, password) are managed in an external `config.ini` file, keeping sensitive credentials out of the source code.

*   **Tenant Filtering**:
    *   Use the `--tenant` flag to focus the view on a single tenant, simplifying analysis in large environments.

## Setup

1.  **Install Dependencies**:
    This project uses `requests`, `rich`, and `textual`. You can install them using `pip` or your preferred package manager.
    - Using `pip`:
      ```shell
      pip install requests rich textual
      ```
    - Using `uv` (recommended for speed):
      ```shell
      uv pip install requests rich textual
      ```

2.  **Create Configuration File**:
    In the same directory as the script, create a file named `config.ini` with your APIC connection details:
    ```ini
    [ACI]
    URL = https://<your-apic-ip>
    USER = <your-username>
    PASSWORD = <your-password>
    ```

## Usage

The script can be run directly with `python` or using a project runner like `uv`. The examples below use `uv`.

### Command-Line Options

```
aci-treeviwer % uv run aci-v2.py --help
usage: aci-v2.py [-h] [--tenant TENANT]

ACI Audit Visualizer

options:
  -h, --help            show this help message and exit
  --tenant TENANT       Filter by Tenant name
```
## Output example
```
aci-treeviwer % uv run aci-v2.py
[*] Connected to https://192.168.200.131
ACI Audit Topology Report (with Service Graph & pcTag)
├── Tenant: mgmt
│   ├── VRF: oob (VNID: 2457600, pcTag: 49153)
│   │   ├── Internal Network & Security
│   │   └── External Connectivity (L3Out)
│   └── VRF: inb (VNID: 3112960, pcTag: 49153)
│       ├── Internal Network & Security
│       │   └── BD: inb (pcTag: 16386)
│       └── External Connectivity (L3Out)
│           └── L3Out: L3_INB
│               ├── Advertised: 192.168.100.254/24, 0.0.0.0/0 (pcTag:15)
│               └── External EPG: L3_EPG_INB (pcTag: 49158)
│                   ├── Subnet: 0.0.0.0/0 (pcTag: N/A, Scope: External EPG)
│                   ├── Provides: ALL_common (Bi)
│                   └── Consumes: ALL_common (Bi)
├── Tenant: infra
│   ├── VRF: overlay-1 (VNID: 16777199, pcTag: 16386)
│   │   ├── Internal Network & Security
│   │   │   └── BD: default (pcTag: 49153)
│   │   │       └── EPG: default (pcTag: 49154)
│   │   └── External Connectivity (L3Out)
│   └── VRF: ave-ctrl (VNID: 2162688, pcTag: 16386)
│       ├── Internal Network & Security
│       │   └── BD: ave-ctrl (pcTag: 32770)
│       │       └── EPG: ave-ctrl (pcTag: 49153)
│       └── External Connectivity (L3Out)
├── Tenant: common
│   ├── VRF: copy (VNID: 3112961, pcTag: 32770)
│   │   ├── Internal Network & Security
│   │   └── External Connectivity (L3Out)
│   ├── VRF: default (VNID: 2883584, pcTag: 16386)
│   │   ├── Internal Network & Security
│   │   └── External Connectivity (L3Out)
│   └── VRF: V1 (VNID: 2228224, pcTag: 16386)
│       ├── Internal Network & Security
│       └── External Connectivity (L3Out)
│           └── L3Out: L3out_Common
│               ├── Advertised: 172.16.1.254/24
│               └── External EPG: L3out_Common (pcTag: 5481)
│                   ├── Subnet: 20.1.1.1/32 (pcTag: N/A, Scope: External EPG, Shared Route Control, Shared Security)
│                   └── Provides: Common_Mang (Bi)
├── Tenant: T1
│   ├── VRF: V1 (VNID: 2818048, pcTag: 32770)
│   │   ├── vzAny (VRF Contracts)
│   │   │   ├── Provides: T1_L4-1_Ser1_PBR_Vzany (Bi)
│   │   │   ├── Provides: L3out1 (Bi)
│   │   │   ├── Consumes: Shared_Contract (Bi)
│   │   │   └── Consumes: L3out_SSL (Bi)
│   │   ├── Internal Network & Security
│   │   │   └── BD: 172_16_1_0 (pcTag: 49153)
│   │   │       └── EPG: T1_V1_E1 (pcTag: 16389)
│   │   └── External Connectivity (L3Out)
│   │       └── L3Out: L3out1_T1_V1
│   │           ├── Advertised: 172.16.1.254/24, 0.0.0.0/0 (pcTag:15)
│   │           └── External EPG: L3out1_T1_V1_EPG (pcTag: 49162)
│   │               ├── Subnet: 0.0.0.0/0 (pcTag: N/A, Scope: External EPG)
│   │               ├── Consumes: T1_L4-1_Ser1_PBR_Vzany (Bi)
│   │               └── Consumes: L3out1 (Bi)
│   ├── VRF: V2 (VNID: 3047424, pcTag: 32770)
│   │   ├── vzAny (VRF Contracts)
│   │   │   ├── Provides: L3out1 (Bi)
│   │   │   ├── Consumes: Shared_Contract (Bi)
│   │   │   └── Consumes: L3out_SSL (Bi)
│   │   ├── Internal Network & Security
│   │   │   └── BD: 172_16_2_0 (pcTag: 32771)
│   │   │       └── EPG: T1_V2_E2 (pcTag: 32773)
│   │   └── External Connectivity (L3Out)
│   │       └── L3Out: L3out2_T1_V2
│   │           ├── Advertised: 172.16.2.254/24, 0.0.0.0/0 (pcTag:15)
│   │           └── External EPG: L3out2_T1_V2_EPG (pcTag: 32774)
│   │               ├── Subnet: 0.0.0.0/0 (pcTag: N/A, Scope: External EPG)
│   │               ├── Provides: L3out1 (Bi)
│   │               └── Consumes: L3out1 (Bi)
│   ├── VRF: Shared_VRF (VNID: 2949120, pcTag: 49153)
│   │   ├── Internal Network & Security
│   │   └── External Connectivity (L3Out)
│   │       └── L3Out: L3out_Shared
│   │           ├── Advertised: Private Only
│   │           └── External EPG: L3out_Shared_EPG (pcTag: 10932)
│   │               ├── Subnet: 20.1.1.1/32 (pcTag: N/A, Scope: External EPG, Shared Route Control, Shared Security)
│   │               └── Provides: Shared_Contract (Bi)
│   └── VRF: Shared_SSL (VNID: 2523136, pcTag: 16386)
│       ├── Internal Network & Security
│       └── External Connectivity (L3Out)
│           └── L3Out: L3out_SSL
│               ├── Advertised: Private Only
│               └── External EPG: L3out_SSL_EPG (pcTag: 22)
│                   ├── Subnet: 10.1.8.0/24 (pcTag: N/A, Scope: External EPG, Shared Route Control, Shared Security)
│                   ├── Subnet: 172.1.10.0/24 (pcTag: N/A, Scope: External EPG, Shared Route Control, Shared Security)
│                   └── Provides: L3out_SSL (Bi)
├── Tenant: T2
│   └── VRF: T2_V1 (VNID: 2883585, pcTag: 49153)
│       ├── vzAny (VRF Contracts)
│       │   ├── Consumes: Common_Mang (Bi)
│       │   └── Consumes: L3out_T2 (Bi)
│       ├── Internal Network & Security
│       │   └── BD: 172_16_3_0 (pcTag: 16386)
│       │       └── EPG: T2_V1_E1 (pcTag: 32770)
│       │           └── Provides: L3out_T2 (Bi)
│       └── External Connectivity (L3Out)
│           ├── L3Out: L3out_T2
│           │   ├── Advertised: 172.16.3.254/24, 0.0.0.0/0 (pcTag:15)
│           │   └── External EPG: L3out_T2_EPG (pcTag: 32771)
│           │       ├── Subnet: 0.0.0.0/0 (pcTag: N/A, Scope: External EPG)
│           │       └── Consumes: L3out_T2 (Bi)
│           └── L3Out: L3out_FW_T2
│               ├── Advertised: 172.16.3.254/24
│               └── External EPG: L3out_FW_EPG (pcTag: 49154)
│                   ├── Subnet: 172.16.4.0/24 (pcTag: N/A, Scope: External EPG)
│                   └── Provides: L3out_T2 (Bi)
└── Tenant: T3
    └── VRF: T3_V1 (VNID: 3112962, pcTag: 49153)
        ├── vzAny (VRF Contracts)
        │   ├── Consumes: Common_Mang (Bi)
        │   └── Consumes: L3out_T3 (Bi)
        ├── Internal Network & Security
        │   └── BD: 172_16_4_0 (pcTag: 32770)
        │       └── EPG: T3_V1_E1 (pcTag: 49154)
        │           └── Provides: L3out_T3 (Bi)
        └── External Connectivity (L3Out)
            ├── L3Out: L3out_T3_V1
            │   ├── Advertised: 172.16.4.254/24, 0.0.0.0/0 (pcTag:15)
            │   └── External EPG: L3out_T3_EPG (pcTag: 32771)
            │       ├── Subnet: 0.0.0.0/0 (pcTag: N/A, Scope: External EPG)
            │       └── Consumes: L3out_T3 (Bi)
            └── L3Out: L3out_FW_T3
                ├── Advertised: 172.16.4.254/24
                └── External EPG: L3out_FW_T3_EPG (pcTag: 32772)
                    ├── Subnet: 172.16.3.0/24 (pcTag: N/A, Scope: External EPG)
                    └── Provides: L3out_T3 (Bi)
```

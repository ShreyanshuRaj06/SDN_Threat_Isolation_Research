# SETUP: Run the lab locally

The repo has no `package.json`/`Makefile` yet, so these steps set up the **lab tools**. Verify package names and versions against each tool's official docs; Ryu in particular can constrain the Python version (check its current release notes).

## Prerequisites
- Linux (Ubuntu LTS recommended). **Mac/Windows:** use a Linux VM, or WSL2 on Windows (OVS kernel features and inline Suricata can be limited there; a full VM is safer).
- Python 3 (a version supported by your Ryu release), pip, git.
- 16 GB RAM is a prototype host, not a capacity guarantee.
- Optional: AWS account (disposable) for Phase 5.

## 1. Clone and environment
```bash
git clone <your-repo-url> sdn-threat-isolation && cd sdn-threat-isolation
cp .env.example .env
```
Windows PowerShell: `Copy-Item .env.example .env` (inside the Linux VM/WSL2 use the command above).

## 2. Install tools (Ubuntu)
```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch suricata wireshark tshark
python3 -m venv .venv && source .venv/bin/activate
pip install ryu
```
`pip install ryu` may fail on newer Python versions; use a venv with a Python version Ryu supports.

## 3. Start the controller and lab
```bash
ryu-manager path/to/your_ryu_app.py                 # terminal 1
sudo mn --controller=remote,ip=127.0.0.1,port=6653 \
        --switch ovsk,protocols=OpenFlow13 --topo single,3   # terminal 2
```

## 4. Inspect
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
sudo tail -f /var/log/suricata/eve.json
```

## 5. Database, migrations, seed
No migration tooling exists yet. When added, follow DATABASE.md section 6.

## 6. Tests & Model Training
- **Unit test suite:** `pytest tests/` (48 tests passing across all components).
- **Stage verification scripts:** `python3 experiments/verify_stage[1-6].py`.
- **Pretrained models download:** Grab serialized weights (`.pkl`, `.pt`) from [GitHub Releases v1.0.0](https://github.com/ShreyanshuRaj06/SDN_Threat_Isolation_Research/releases/tag/v1.0.0).
- **End-to-end multi-model training:** `python3 experiments/train_models.py --cns2022 --samples 100000`.
- **Google Colab 1-click training:** Open `notebooks/SDN_Threat_Isolation_Research_Colab.ipynb` in Colab.

## Common errors and fixes
| # | Error | Fix |
|---|---|---|
| 1 | `mn: command not found` | Install `mininet`; open a new shell |
| 2 | `Exception: Could not find a default OpenFlow controller` | Start Ryu first or use `--controller=remote` |
| 3 | Switch connects, no flows | Match protocol version: `protocols=OpenFlow13` and a Ryu app using OFP 1.3 |
| 4 | `pip install ryu` fails / import errors | Use a Python version your Ryu supports; fresh venv |
| 5 | Port 6653 in use | `sudo lsof -i :6653`; stop the old controller |
| 6 | Stale Mininet state | `sudo mn -c` |
| 7 | `ovs-vsctl: database connection failed` | `sudo systemctl start openvswitch-switch` |
| 8 | Suricata runs but nothing is dropped | Passive mode only observes; configure inline IPS and `drop` rules, and ensure both directions traverse the sensor |
| 9 | eve.json missing/empty | Confirm EVE output is enabled in suricata.yaml and the path/permissions |
| 10 | Permission denied reading logs/pcaps | Run with proper group/sudo; never loosen permissions on captures with credentials |
| 11 | Wireshark sees nothing | Select the right interface; capture on veth/bridge in the lab |

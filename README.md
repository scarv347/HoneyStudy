# HoneyStudy

A Python honeypot research project for studying unsolicited traffic through simulated services, preserved event records, heuristic analysis, and a private dashboard. Includes HTTP decoys, protocol adapters, a collector, reporting tools, and tests from Scott Carver's home-built deployment.

## Try it locally

Requires Python 3.11+ on Linux. No third-party packages are required for the local demo.

```sh
python3 demo.py
```

Open **http://127.0.0.1:9090** for a dashboard with synthetic events. HTTP decoys run on loopback ports **8080–8083** and write JSON logs under `state/`. Stop with Ctrl+C. If port 9090 is occupied, use `python3 demo.py --dashboard-port 19090`. The demo does not modify system services, open firewall ports, contact a cloud host, or download threat feeds. Dashboard events are labeled fixtures, not a live connection to the decoy logs. The fixture address is illustrative; it is not contacted or an attribution.

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Code overview

- **Simulation:** `decoy.py`, `personas.py`, `php_*`, `ftp_decoy.py`, and protocol adapters model service responses without executing captured payloads.
- **Collection & analysis:** `collector.py`, `analysis.py`, `classification.py`, `payload_profile.py`, and `hub.py` normalize and index observations.
- **Dashboard & reports:** `dashboard.html`, `serve.py`, publication, export, history, and rendering modules present the results.
- **Deployment components:** `ship.py` and hub scripts support multi-sensor forwarding. They require operator-provided configuration and credentials; the original deployment configuration is not included.

This is a source release with a local demonstration, not a one-command internet deployment. Use a separate, isolated environment for exposed sensors; keep administration, dashboards, credentials, and captured data private. Captured payloads must remain inert. Detection labels are heuristics, not proof of exploitation. Review the code and design isolation and retention before public exposure.

Optional geolocation databases, map boundaries, third-party honeypot engines such as Cowrie, and live evidence are not bundled. The demo map has no geographic boundaries.

## About the author

I'm **Scott Carver**, a Computer Systems Engineering student at Arizona State University focused on cybersecurity. HoneyStudy reflects my interests in security operations, infrastructure, Linux, and learning through practical projects.

**Read more on my portfolio:** full project write-up coming soon; the portfolio is not published yet.

[GitHub](https://github.com/scarv347) · [LinkedIn](https://www.linkedin.com/in/scott-carver0/)

## License

[MIT](LICENSE) · Copyright © 2026 Scott Carver.

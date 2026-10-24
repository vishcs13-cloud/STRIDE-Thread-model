#!/usr/bin/env python3
"""
STRIDE Threat Model Study - Microservice Data Flows
===================================================
This script
  1. describes an e-commerce microservice system as a Data Flow Diagram (DFD),
  2. applies the STRIDE-per-element method to generate threats automatically,
  3. scores each threat (likelihood x impact) and checks existing controls,
  4. exports the model in OWASP Threat Dragon (v2) JSON format,
  5. exports a CSV threat register, a DFD image and summary charts.

Run:  python stride_threat_model.py            (results go to ./output)
"""
import argparse
import csv
import json
import math
import os
import uuid
from collections import Counter, defaultdict

import matplotlib

matplotlib.use("Agg")  # draw to files, no window needed
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, FancyArrowPatch, Rectangle

# ----------------------------------------------------------------------------
# 1. STRIDE basics
# ----------------------------------------------------------------------------
STRIDE = ["Spoofing", "Tampering", "Repudiation",
          "Information disclosure", "Denial of service",
          "Elevation of privilege"]

# STRIDE-per-element: which categories apply to which DFD element type
APPLICABLE = {
    "actor":   ["Spoofing", "Repudiation"],
    "process": STRIDE,
    "store":   ["Tampering", "Repudiation", "Information disclosure",
                "Denial of service"],
    "flow":    ["Tampering", "Information disclosure", "Denial of service"],
}

# ----------------------------------------------------------------------------
# 2. Threat templates: (element type, STRIDE category) -> generic threat
#    L = base likelihood (1-5), I = base impact (1-5),
#    control = the security control that mitigates this threat
# ----------------------------------------------------------------------------
T = {}


def add(kind, cat, title, desc, mitigation, L, I, control):
    T[(kind, cat)] = dict(title=title, desc=desc, mitigation=mitigation,
                          L=L, I=I, control=control)


add("actor", "Spoofing", "Impersonation of {name}",
    "An attacker uses stolen, guessed or phished credentials or session "
    "tokens to act as {name}.",
    "Enforce MFA, strong password policy, short-lived tokens, login "
    "anomaly detection.", 3, 4, "mfa")
add("actor", "Repudiation", "{name} denies performing an action",
    "{name} claims an order, payment or change was never made and the "
    "system cannot prove otherwise.",
    "Tamper-evident audit logs with user ID, time and source IP.",
    2, 3, "audit_log")

add("process", "Spoofing", "Spoofed caller or fake instance of {name}",
    "A rogue service or attacker impersonates a trusted caller of {name}, "
    "or pretends to be {name}.",
    "Mutual TLS between services, signed JWTs, service mesh identity.",
    3, 4, "authn")
add("process", "Tampering", "Malicious input or code change in {name}",
    "Injection or parameter tampering, or a modified image/config, changes "
    "how {name} behaves.",
    "Input and schema validation, signed container images, immutable "
    "deployments.", 3, 4, "input_validation")
add("process", "Repudiation", "Missing audit trail in {name}",
    "Actions handled by {name} are not logged, so incidents cannot be "
    "investigated or users held accountable.",
    "Central, append-only structured logging with correlation IDs.",
    3, 3, "audit_log")
add("process", "Information disclosure", "Data leakage from {name}",
    "Verbose errors, debug endpoints or logs of {name} reveal secrets "
    "or personal data.",
    "Generic error messages, log scrubbing, secrets manager.",
    3, 4, "output_filtering")
add("process", "Denial of service", "Resource exhaustion of {name}",
    "Request flooding or heavy calls exhaust CPU, memory or threads of "
    "{name}.",
    "Rate limiting, timeouts, circuit breakers, autoscaling.",
    3, 3, "rate_limit")
add("process", "Elevation of privilege", "Broken access control in {name}",
    "A low-privileged caller performs admin or cross-user operations "
    "in {name}.",
    "RBAC/ABAC check on every request, least-privilege service accounts.",
    3, 5, "rbac")

add("store", "Tampering", "Unauthorised modification of data in {name}",
    "SQL injection or a stolen DB account lets an attacker change or "
    "delete records in {name}.",
    "Least-privilege DB accounts, parameterised queries, integrity checks.",
    3, 4, "db_access_control")
add("store", "Repudiation", "Untraceable changes in {name}",
    "Changes to {name} are not logged, so who changed what is unknown.",
    "Database audit logging and change history.", 2, 3, "audit_log")
add("store", "Information disclosure", "Data theft from {name}",
    "Stolen backups, direct access or injection expose data stored in "
    "{name}.",
    "Encryption at rest, field-level encryption for PII, network isolation.",
    3, 5, "encryption_at_rest")
add("store", "Denial of service", "{name} unavailable or destroyed",
    "Ransomware, disk exhaustion or an outage makes {name} unusable.",
    "Backups, replication, resource quotas.", 2, 4, "backup_ha")

add("flow", "Tampering", "Data modified in transit on {name}",
    "A man-in-the-middle changes messages travelling over {name}.",
    "TLS 1.2+ or mutual TLS, message signing.", 3, 4, "tls")
add("flow", "Information disclosure", "Eavesdropping on {name}",
    "Network sniffing exposes tokens, personal or payment data sent "
    "over {name}.",
    "TLS 1.2+ or mutual TLS for every hop, including internal ones.",
    3, 4, "tls")
add("flow", "Denial of service", "Flooding or blocking of {name}",
    "Excess traffic or dropped connections interrupt {name}.",
    "Rate limiting, quotas, retry with back-off.", 2, 3, "rate_limit")

# Extra rule: a flow without caller authentication can be spoofed
EXTRA_UNAUTH = dict(
    title="Unauthenticated data flow {name}",
    desc="Messages on {name} are accepted without verifying the sender, "
         "so an attacker can forge them.",
    mitigation="Verify sender identity: signed requests (HMAC), mutual TLS "
               "or broker credentials.",
    L=4, I=5, control="authn")

# ----------------------------------------------------------------------------
# 3. The system under study: "ShopSphere" e-commerce microservices
# ----------------------------------------------------------------------------
# kind: actor | process | store ; pos = (x, y) on a 170 x 100 drawing grid
# sensitivity (1-5) = how sensitive the data handled is
# controls = security controls that already exist
E = []


def element(eid, name, kind, zone, pos, sens, controls, internet=False,
            desc=""):
    E.append(dict(id=eid, name=name, kind=kind, zone=zone, pos=pos,
                  sensitivity=sens, controls=set(controls),
                  internet_facing=internet, description=desc))


element("A1", "Customer", "actor", "Internet", (16, 80), 4,
        ["audit_log"], True, "Shopper using web or mobile app")
element("A2", "Admin", "actor", "Internet", (16, 55), 5,
        ["mfa", "audit_log"], True, "Staff member managing the shop")
element("A3", "Payment Provider", "actor", "Internet", (16, 18), 5,
        ["audit_log"], True, "External card-payment provider")
element("P1", "API Gateway", "process", "DMZ", (49, 55), 4,
        ["authn", "input_validation", "audit_log", "rate_limit", "rbac"],
        True, "Single public entry point")
element("P2", "Auth Service", "process", "Internal", (84, 86), 5,
        ["authn", "input_validation", "audit_log", "rbac"],
        desc="Logins and tokens")
element("P3", "Order Service", "process", "Internal", (84, 58), 4,
        ["authn", "input_validation", "rbac"], desc="Order handling")
element("P4", "Payment Service", "process", "Internal", (84, 22), 5,
        ["authn", "input_validation", "audit_log", "rbac",
         "output_filtering"], desc="Payment processing")
element("P5", "Inventory Service", "process", "Internal", (125, 46), 2,
        ["authn", "input_validation", "rate_limit"], desc="Stock levels")
element("P6", "Notification Service", "process", "Internal", (155, 22), 3,
        ["input_validation"], desc="Email and SMS messages")
element("S1", "Users DB", "store", "Internal", (125, 86), 5,
        ["db_access_control", "encryption_at_rest", "audit_log",
         "backup_ha"], desc="Accounts and password hashes")
element("S2", "Orders DB", "store", "Internal", (125, 70), 4,
        ["db_access_control", "backup_ha"], desc="Orders and addresses")
element("S3", "Inventory DB", "store", "Internal", (155, 46), 2,
        ["db_access_control", "backup_ha"], desc="Product stock")
element("S4", "Message Broker", "store", "Internal", (125, 22), 3,
        ["backup_ha"], desc="Queue for order events")

NAMES = {e["id"]: e["name"] for e in E}
ZONES = {e["id"]: e["zone"] for e in E}

# Data flows: (id, label, source, target, protocol, encrypted, authenticated,
#              public network, rate limited, sensitivity)
FLOW_ROWS = [
    ("F1", "Browse and checkout", "A1", "P1", "HTTPS", 1, 1, 1, 1, 4),
    ("F2", "Admin console", "A2", "P1", "HTTPS", 1, 1, 1, 1, 5),
    ("F3", "Token validation", "P1", "P2", "HTTP", 0, 1, 0, 0, 5),
    ("F4", "Order API", "P1", "P3", "HTTPS (mTLS)", 1, 1, 0, 1, 4),
    ("F5", "Order SQL queries", "P3", "S2", "SQL", 0, 1, 0, 0, 4),
    ("F6", "Stock check", "P3", "P5", "gRPC", 1, 1, 0, 1, 2),
    ("F7", "Stock SQL queries", "P5", "S3", "SQL (TLS)", 1, 1, 0, 0, 2),
    ("F8", "Charge request", "P3", "P4", "HTTPS", 1, 1, 0, 1, 5),
    ("F9", "Card payment API", "P4", "A3", "HTTPS", 1, 1, 1, 1, 5),
    ("F10", "Payment webhook", "A3", "P4", "HTTPS", 1, 0, 1, 0, 5),
    ("F11", "Credential lookup", "P2", "S1", "SQL (TLS)", 1, 1, 0, 0, 5),
    ("F12", "Publish order event", "P3", "S4", "AMQP", 0, 0, 0, 0, 3),
    ("F13", "Consume order event", "S4", "P6", "AMQP", 0, 0, 0, 0, 3),
    ("F14", "Email / SMS to customer", "P6", "A1", "SMTP/SMS", 0, 1, 1, 0, 3),
]

FLOWS = []
for (fid, label, s, t, proto, enc, auth, pub, rate, sens) in FLOW_ROWS:
    ctrl = set()
    if enc:
        ctrl.add("tls")
    if rate:
        ctrl.add("rate_limit")
    if auth:
        ctrl.add("authn")
    crosses = ZONES[s] != ZONES[t]
    FLOWS.append(dict(
        id=fid, name=f"{fid} {label}", kind="flow", src=s, dst=t,
        protocol=proto, encrypted=bool(enc), authenticated=bool(auth),
        public=bool(pub), sensitivity=sens, controls=ctrl,
        internet_facing=bool(pub),
        zone="Crosses boundary" if crosses else ZONES[s],
        description=f"{NAMES[s]} -> {NAMES[t]} ({proto})"))

# Trust boundaries (x, y, width, height) on the drawing grid
BOUNDARIES = [("Internet zone", 2, 4, 28, 92),
              ("DMZ", 38, 40, 22, 30),
              ("Internal network", 66, 4, 100, 92)]
SIZE = {"actor": (8, 4), "process": (10, 5), "store": (10, 3.5)}  # half sizes


# ----------------------------------------------------------------------------
# 4. Threat generation and scoring
# ----------------------------------------------------------------------------
def severity(score):
    return "High" if score >= 15 else "Medium" if score >= 8 else "Low"


def build_threat(item, cat, tpl):
    likelihood = min(5, tpl["L"] + (1 if item["internet_facing"] else 0))
    impact = min(5, tpl["I"] + (1 if item["sensitivity"] >= 4 else 0))
    inherent = likelihood * impact
    mitigated = tpl["control"] in item["controls"]
    risk = impact * 1 if mitigated else inherent  # residual likelihood = 1
    return dict(
        component=item["name"], component_id=item["id"],
        component_type=item["kind"], zone=item["zone"], category=cat,
        title=tpl["title"].format(name=item["name"]),
        description=tpl["desc"].format(name=item["name"]),
        likelihood=likelihood, impact=impact, inherent_score=inherent,
        status="Mitigated" if mitigated else "Open",
        risk_score=risk, severity=severity(risk),
        mitigation=tpl["mitigation"], missing_control=tpl["control"])


def generate_threats():
    threats = []
    for item in E + FLOWS:
        for cat in APPLICABLE[item["kind"]]:
            threats.append(build_threat(item, cat, T[(item["kind"], cat)]))
        if item["kind"] == "flow" and not item["authenticated"]:
            threats.append(build_threat(item, "Spoofing", EXTRA_UNAUTH))
    for n, t in enumerate(threats, 1):
        t["id"] = f"T{n:03d}"
    return threats


# ----------------------------------------------------------------------------
# 5. Exports: CSV, OWASP Threat Dragon JSON
# ----------------------------------------------------------------------------
CSV_COLS = ["id", "component", "component_type", "zone", "category", "title",
            "description", "likelihood", "impact", "inherent_score",
            "status", "risk_score", "severity", "mitigation"]


def write_csv(threats, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(threats)


def write_threat_dragon(threats, path):
    """Create a Threat Dragon v2 model file (open it with 'Open a threat
    model' in the Threat Dragon web or desktop app)."""
    by_comp = defaultdict(list)
    for t in threats:
        by_comp[t["component_id"]].append(t)
    ids = {}            # our id -> cell uuid
    cells, z, number = [], 1, 0
    SC = 9              # grid units -> pixels

    def td_threats(cid):
        nonlocal number
        out = []
        for t in by_comp[cid]:
            number += 1
            out.append(dict(
                id=str(uuid.uuid4()), title=t["title"], status=t["status"],
                severity=t["severity"], type=t["category"],
                description=t["description"], mitigation=t["mitigation"],
                modelType="STRIDE", new=False, number=number,
                score=str(t["risk_score"])))
        return out

    for name, x, y, w, h in BOUNDARIES:
        cells.append(dict(
            shape="trust-boundary-box", id=str(uuid.uuid4()), zIndex=0,
            position=dict(x=x * SC, y=(100 - y - h) * SC),
            size=dict(width=w * SC, height=h * SC), visible=True,
            attrs=dict(headerText=dict(text=name)),
            data=dict(type="tm.BoundaryBox", name=name,
                      description="", isTrustBoundary=True,
                      hasOpenThreats=False)))

    shape_of = {"actor": "actor", "process": "process", "store": "store"}
    type_of = {"actor": "tm.Actor", "process": "tm.Process",
               "store": "tm.Store"}
    for e in E:
        z += 1
        cid = str(uuid.uuid4())
        ids[e["id"]] = cid
        hw, hh = SIZE[e["kind"]]
        th = td_threats(e["id"])
        data = dict(type=type_of[e["kind"]], name=e["name"],
                    description=e["description"], outOfScope=False,
                    reasonOutOfScope="", threats=th,
                    hasOpenThreats=any(t["status"] == "Open" for t in th))
        if e["kind"] == "actor":
            data["providesAuthentication"] = False
        elif e["kind"] == "process":
            data["privilegeLevel"] = ""
        else:
            data.update(isALog="audit_log" in e["controls"],
                        isEncrypted="encryption_at_rest" in e["controls"],
                        isSigned=False, storesCredentials=e["id"] == "S1",
                        storesInventory=False)
        cells.append(dict(
            shape=shape_of[e["kind"]], id=cid, zIndex=z, visible=True,
            position=dict(x=(e["pos"][0] - hw) * SC * 1.0,
                          y=(100 - e["pos"][1] - hh) * SC),
            size=dict(width=hw * 2 * SC, height=hh * 2 * SC),
            attrs=dict(text=dict(text=e["name"])), data=data))

    for f in FLOWS:
        z += 1
        th = td_threats(f["id"])
        cells.append(dict(
            shape="flow", id=str(uuid.uuid4()), zIndex=z, vertices=[],
            source=dict(cell=ids[f["src"]]), target=dict(cell=ids[f["dst"]]),
            labels=[f["name"]], width=200, height=100,
            data=dict(type="tm.Flow", name=f["name"], description="",
                      outOfScope=False, reasonOutOfScope="",
                      protocol=f["protocol"], isBidirectional=False,
                      isEncrypted=f["encrypted"],
                      isPublicNetwork=f["public"], threats=th,
                      hasOpenThreats=any(t["status"] == "Open"
                                         for t in th))))

    model = dict(
        version="2.5.0",
        summary=dict(title="ShopSphere Microservices STRIDE Model",
                     owner="Student Project",
                     description="STRIDE-per-element threat model of an "
                                 "e-commerce microservice system.",
                     id=0),
        detail=dict(contributors=[], diagrams=[dict(
            id=0, title="ShopSphere data flow diagram",
            diagramType="STRIDE",
            placeholder="STRIDE data flow diagram",
            thumbnail="./public/content/images/thumbnail.stride.jpg",
            version="2.5.0", cells=cells)],
            diagramTop=1, reviewer="", threatTop=number))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(model, f, indent=2)


# ----------------------------------------------------------------------------
# 6. Pictures: DFD and summary charts
# ----------------------------------------------------------------------------
def _edge(center, half, other, ellipse):
    dx, dy = other[0] - center[0], other[1] - center[1]
    if ellipse:
        s = 1 / math.sqrt((dx / half[0]) ** 2 + (dy / half[1]) ** 2)
    else:
        s = min(half[0] / abs(dx) if dx else 1e9,
                half[1] / abs(dy) if dy else 1e9)
    return center[0] + dx * s, center[1] + dy * s


def draw_dfd(path):
    fig, ax = plt.subplots(figsize=(17, 10))
    ax.set_xlim(0, 170)
    ax.set_ylim(0, 100)
    ax.axis("off")
    for name, x, y, w, h in BOUNDARIES:
        ax.add_patch(Rectangle((x, y), w, h, fill=False, ls="--", lw=1.6,
                               ec="#6d4c41"))
        ty = y + 1.2 if name == "DMZ" else y + h - 2.2
        ax.text(x + 1, ty, name, color="#6d4c41", fontsize=11,
                weight="bold")
    pos = {e["id"]: e["pos"] for e in E}
    kind = {e["id"]: e["kind"] for e in E}
    for e in E:
        x, y = e["pos"]
        hw, hh = SIZE[e["kind"]]
        if e["kind"] == "actor":
            ax.add_patch(Rectangle((x - hw, y - hh), 2 * hw, 2 * hh,
                                   fc="#e3f2fd", ec="#1565c0", lw=1.8))
        elif e["kind"] == "process":
            ax.add_patch(Ellipse((x, y), 2 * hw, 2 * hh, fc="#e8f5e9",
                                 ec="#2e7d32", lw=1.8))
        else:  # data store: open-ended box (two parallel lines)
            ax.add_patch(Rectangle((x - hw, y - hh), 2 * hw, 2 * hh,
                                   fc="#fff8e1", ec="none"))
            for yy in (y - hh, y + hh):
                ax.plot([x - hw, x + hw], [yy, yy], color="#ef6c00", lw=2)
        ax.text(x, y, e["name"], ha="center", va="center", fontsize=9,
                weight="bold")
    curved = {"F9": 0.15, "F10": 0.15}
    for f in FLOWS:
        a, b = pos[f["src"]], pos[f["dst"]]
        ea = _edge(a, SIZE[kind[f["src"]]], b, kind[f["src"]] == "process")
        eb = _edge(b, SIZE[kind[f["dst"]]], a, kind[f["dst"]] == "process")
        weak = not (f["encrypted"] and f["authenticated"])
        col = "#c62828" if weak else "#2e7d32"
        rad = curved.get(f["id"], 0)
        ax.add_patch(FancyArrowPatch(
            ea, eb, arrowstyle="-|>", mutation_scale=16, lw=1.7, color=col,
            ls="--" if weak else "-", connectionstyle=f"arc3,rad={rad}"))
        mx, my = (ea[0] + eb[0]) / 2, (ea[1] + eb[1]) / 2
        dx, dy = eb[0] - ea[0], eb[1] - ea[1]
        mx += 0.5 * rad * dy
        my -= 0.5 * rad * dx
        ax.text(mx, my, f["id"], fontsize=9, ha="center", va="center",
                color=col, weight="bold",
                bbox=dict(boxstyle="round,pad=0.15", fc="white", ec=col))
    ax.legend(handles=[
        plt.Line2D([0], [0], color="#2e7d32", lw=2,
                   label="Flow with TLS and authentication"),
        plt.Line2D([0], [0], color="#c62828", lw=2, ls="--",
                   label="Weak flow (no TLS or no authentication)")],
        loc="upper center", bbox_to_anchor=(0.5, 0.0), ncol=2, fontsize=10,
        frameon=True)
    ax.set_title("ShopSphere - Data Flow Diagram with Trust Boundaries",
                 fontsize=15, weight="bold")
    fig.savefig(path, dpi=130, bbox_inches="tight")
    plt.close(fig)


def draw_summary(threats, path):
    fig, axes = plt.subplots(1, 3, figsize=(19, 5.8))
    # (a) threats per STRIDE category by status
    cats = [c for c in STRIDE]
    op = [sum(1 for t in threats if t["category"] == c and
              t["status"] == "Open") for c in cats]
    mi = [sum(1 for t in threats if t["category"] == c and
              t["status"] == "Mitigated") for c in cats]
    short = ["Spoofing", "Tampering", "Repudiation", "Info\ndisclosure",
             "Denial of\nservice", "Elevation of\nprivilege"]
    axes[0].bar(short, op, color="#c62828", label="Open")
    axes[0].bar(short, mi, bottom=op, color="#2e7d32", label="Mitigated")
    axes[0].set_title("Threats per STRIDE category")
    axes[0].set_ylabel("Number of threats")
    axes[0].legend()
    axes[0].tick_params(axis="x", labelsize=8)
    # (b) severity of open threats
    sev = Counter(t["severity"] for t in threats if t["status"] == "Open")
    labels = ["High", "Medium", "Low"]
    vals = [sev.get(s, 0) for s in labels]
    axes[1].bar(labels, vals, color=["#c62828", "#ef6c00", "#f9a825"])
    for i, v in enumerate(vals):
        axes[1].text(i, v + 0.3, str(v), ha="center")
    axes[1].set_title("Severity of open threats")
    # (c) riskiest components (sum of open risk scores)
    tot = defaultdict(int)
    for t in threats:
        if t["status"] == "Open":
            tot[t["component"]] += t["risk_score"]
    top = sorted(tot.items(), key=lambda kv: kv[1])[-10:]
    axes[2].barh([k for k, _ in top], [v for _, v in top], color="#1565c0")
    axes[2].set_title("Top 10 components by open risk")
    axes[2].set_xlabel("Sum of open risk scores")
    axes[2].tick_params(axis="y", labelsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


# ----------------------------------------------------------------------------
# 7. Summary and main
# ----------------------------------------------------------------------------
def summarise(threats):
    open_t = [t for t in threats if t["status"] == "Open"]
    return dict(
        total_threats=len(threats),
        open=len(open_t),
        mitigated=len(threats) - len(open_t),
        open_by_severity={s: sum(1 for t in open_t if t["severity"] == s)
                          for s in ("High", "Medium", "Low")},
        by_category={c: sum(1 for t in threats if t["category"] == c)
                     for c in STRIDE},
        open_by_category={c: sum(1 for t in open_t if t["category"] == c)
                          for c in STRIDE},
        elements=len(E), flows=len(FLOWS))


def main():
    ap = argparse.ArgumentParser(description="STRIDE threat model generator")
    ap.add_argument("--out", default="output", help="output folder")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    threats = generate_threats()
    write_csv(threats, os.path.join(args.out, "threats.csv"))
    write_threat_dragon(threats, os.path.join(args.out,
                                              "threat_dragon_model.json"))
    draw_dfd(os.path.join(args.out, "dfd.png"))
    draw_summary(threats, os.path.join(args.out, "risk_summary.png"))
    summary = summarise(threats)
    with open(os.path.join(args.out, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print("STRIDE THREAT MODEL - RESULTS")
    print("=" * 60)
    print(f"DFD elements: {summary['elements']}   data flows: "
          f"{summary['flows']}")
    print(f"Threats: {summary['total_threats']}  (open "
          f"{summary['open']}, mitigated {summary['mitigated']})")
    print("Open by severity:", summary["open_by_severity"])
    print("\nTop 10 open threats")
    top = sorted([t for t in threats if t["status"] == "Open"],
                 key=lambda t: -t["risk_score"])[:10]
    for t in top:
        print(f"  {t['id']} [{t['severity']:6}] {t['risk_score']:2} "
              f"{t['category']:<24} {t['title']}")
    print(f"\nFiles saved in: {os.path.abspath(args.out)}")


if __name__ == "__main__":
    main()

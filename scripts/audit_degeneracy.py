#!/usr/bin/env python3
"""Stand-alone vector-level audit of CIC flow CSV/Parquet files.

Reproduces Tables 4 and 5 of "Configuration Fingerprints in Flow-Based Slow-HTTP Detection":
distinct feature vectors per class and label conflicts under four schemas
(30 canonical fields; all flow features; + destination port and protocol; + timestamp),
plus SHA-256 digests of every input and the destination-port profile of each slow-HTTP class.

Usage
  python audit_degeneracy.py FILE [FILE ...] --out audit_out

Inputs (download first; no credentials needed):
  aws s3 cp --no-sign-request "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv" .
  aws s3 cp --no-sign-request "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv" .
  CICIDS2017 MachineLearningCVE: Wednesday-workingHours.pcap_ISCX.csv
  CIC-DoS2017 (Parquet conversion of the CICFlowMeter output)
Requires pandas (and pyarrow for Parquet).
"""
import argparse, hashlib, json, os, sys
import pandas as pd

RAW_FIELDS = {
    "duration": ["Flow Duration"], "fwd_pkts": ["Total Fwd Packets", "Tot Fwd Pkts", "Total Fwd Packet"],
    "bwd_pkts": ["Total Backward Packets", "Tot Bwd Pkts", "Total Bwd packets"],
    "fwd_bytes": ["Total Length of Fwd Packets", "TotLen Fwd Pkts", "Fwd Packets Length Total", "Total Length of Fwd Packet"],
    "bwd_bytes": ["Total Length of Bwd Packets", "TotLen Bwd Pkts", "Bwd Packets Length Total"],
    "fwd_len_mean": ["Fwd Packet Length Mean", "Fwd Pkt Len Mean"], "fwd_len_max": ["Fwd Packet Length Max", "Fwd Pkt Len Max"],
    "fwd_len_min": ["Fwd Packet Length Min", "Fwd Pkt Len Min"], "fwd_len_std": ["Fwd Packet Length Std", "Fwd Pkt Len Std"],
    "bwd_len_mean": ["Bwd Packet Length Mean", "Bwd Pkt Len Mean"], "flow_byts_s": ["Flow Bytes/s", "Flow Byts/s"],
    "flow_pkts_s": ["Flow Packets/s", "Flow Pkts/s"], "flow_iat_mean": ["Flow IAT Mean"], "flow_iat_std": ["Flow IAT Std"],
    "flow_iat_max": ["Flow IAT Max"], "flow_iat_min": ["Flow IAT Min"], "fwd_iat_tot": ["Fwd IAT Total", "Fwd IAT Tot"],
    "fwd_iat_mean": ["Fwd IAT Mean"], "fwd_iat_std": ["Fwd IAT Std"], "fwd_iat_max": ["Fwd IAT Max"], "fwd_iat_min": ["Fwd IAT Min"],
    "bwd_iat_tot": ["Bwd IAT Total", "Bwd IAT Tot"], "bwd_iat_mean": ["Bwd IAT Mean"], "bwd_iat_std": ["Bwd IAT Std"],
    "bwd_iat_max": ["Bwd IAT Max"], "bwd_iat_min": ["Bwd IAT Min"], "active_mean": ["Active Mean"], "active_std": ["Active Std"],
    "idle_mean": ["Idle Mean"], "idle_std": ["Idle Std"]}
META = {"timestamp", "dstport", "destinationport", "protocol", "flowid", "srcip", "sourceip", "dstip",
        "destinationip", "srcport", "sourceport"}
norm = lambda s: "".join(ch for ch in str(s).lower() if ch.isalnum())


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def load(path):
    df = pd.read_parquet(path) if path.endswith(".parquet") else pd.read_csv(path, dtype=str, low_memory=False)
    df = df.astype(str)
    df.columns = [c.strip() for c in df.columns]
    lab = [c for c in df.columns if norm(c) == "label"][0]
    df = df[df[lab].map(norm) != "label"]          # repeated header rows
    return df, lab


def canon_cols(cols):
    lut = {norm(c): c for c in cols}
    out = []
    for k, cands in RAW_FIELDS.items():
        hit = next((lut[norm(c)] for c in cands if norm(c) in lut), None)
        if hit is None:
            raise SystemExit("unresolved canonical field: " + k)
        out.append(hit)
    return out


def audit(path):
    df, lab = load(path)
    allc = [c for c in df.columns if c != lab]
    meta = [c for c in allc if norm(c) in META]
    flow = [c for c in allc if c not in meta]
    pp = [c for c in meta if norm(c) in ("dstport", "destinationport", "protocol")]
    schemas = {"30 canonical fields": canon_cols(allc), "all flow features": flow,
               "flow + port/protocol": flow + pp, "all columns incl. timestamp": allc}
    per_class, conflicts = [], []
    for sname, cols in schemas.items():
        h = pd.util.hash_pandas_object(df[cols], index=False).to_numpy()
        d = pd.DataFrame({"h": h, "lab": df[lab].to_numpy()})
        for L, g in d.groupby("lab"):
            vc = g["h"].value_counts()
            per_class.append({"file": os.path.basename(path), "schema": sname, "label": L, "rows": len(g),
                              "distinct": len(vc), "mean_copies": round(len(g) / len(vc), 4),
                              "top1_share": round(vc.iloc[0] / len(g), 4), "top2_share": round(vc.iloc[:2].sum() / len(g), 4)})
        nl = d.groupby("h")["lab"].nunique()
        bad = nl[nl > 1].index
        pairs = d[d.h.isin(bad)].groupby("h")["lab"].agg(lambda s: " | ".join(sorted(set(s)))).value_counts()
        conflicts.append({"file": os.path.basename(path), "schema": sname, "conflicting_vectors": int(len(bad)),
                          "pairs": json.dumps(pairs.to_dict())})
    ports = []
    pc = next((c for c in df.columns if norm(c) in ("dstport", "destinationport")), None)
    if pc:
        for L, g in df[df[lab].str.contains("slow", case=False)].groupby(lab):
            vc = g[pc].value_counts()
            for port, n in vc.head(10).items():
                ports.append({"file": os.path.basename(path), "label": L, "dst_port": port, "rows": int(n),
                              "share": round(n / len(g), 4)})
    return per_class, conflicts, ports, {"file": os.path.basename(path), "sha256": sha256(path),
                                         "rows_after_header_removal": int(len(df)), "columns": len(df.columns) }


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("files", nargs="+"); ap.add_argument("--out", default="audit_out")
    a = ap.parse_args(); os.makedirs(a.out, exist_ok=True)
    P, C, D, H = [], [], [], []
    for f in a.files:
        print("auditing", f, flush=True)
        p, c, d, h = audit(f); P += p; C += c; D += d; H.append(h)
    pd.DataFrame(P).to_csv(os.path.join(a.out, "distinct_vectors_per_class.csv"), index=False)
    pd.DataFrame(C).to_csv(os.path.join(a.out, "label_conflicts_by_schema.csv"), index=False)
    pd.DataFrame(D).to_csv(os.path.join(a.out, "slow_class_dst_ports.csv"), index=False)
    pd.DataFrame(H).to_csv(os.path.join(a.out, "input_checksums.csv"), index=False)
    print(pd.DataFrame(P).query("label.str.contains('low', case=False)", engine="python").to_string(index=False))
    print(pd.DataFrame(C)[["file", "schema", "conflicting_vectors"]].to_string(index=False))
    print(pd.DataFrame(D).to_string(index=False))
    print(pd.DataFrame(H).to_string(index=False))


if __name__ == "__main__":
    main()

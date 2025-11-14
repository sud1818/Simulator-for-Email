def generate_scan_dataframe(rules):
    """
    rules: dict with keys:
      "keyword_detection", "extension_check", "pattern_matching", "random_noise", "score_threshold"
    Returns: (df, rule_counts) where rule_counts uses human-readable rule names
    """
    data = []
    # Use human-readable keys that match the increments later in the code
    rule_counts = {
        "Keyword Detection": 0,
        "Extension Check": 0,
        "Pattern Matching": 0,
        "Random Noise Rule": 0
    }

    for name in SAFE_NAMES:
        reasons = []
        triggered = []
        # Keyword detection
        if rules.get("keyword_detection", False):
            keywords = ["alpha", "gamma", "sigma", "theta"]
            for k in keywords:
                if k in name.lower():
                    reasons.append(f"keyword:{k}")
                    triggered.append("Keyword Detection")
                    rule_counts["Keyword Detection"] += 1
                    break
        # Extension check
        if rules.get("extension_check", False):
            bad_exts = [".dll", ".bin", ".ps1"]
            if any(name.lower().endswith(e) for e in bad_exts):
                reasons.append("suspicious_ext")
                triggered.append("Extension Check")
                rule_counts["Extension Check"] += 1
        # Pattern matching
        if rules.get("pattern_matching", False):
            # original logic: underscore pattern and no digits
            if "_" in name and not any(ch.isdigit() for ch in name):
                reasons.append("underscore_pattern")
                triggered.append("Pattern Matching")
                rule_counts["Pattern Matching"] += 1
        # Random noise
        if rules.get("random_noise", False):
            if random.random() < 0.18:
                reasons.append("random_noise")
                triggered.append("Random Noise Rule")
                rule_counts["Random Noise Rule"] += 1
        # Suspicious score
        score = compute_score(name, triggered)
        suspicious = score >= rules.get("score_threshold", 50)
        data.append({
            "Type": random.choice(["Process", "File"]),
            "Name": name,
            "Path": f"/demo/cloud/{name}",
            "Suspicious": suspicious,
            "Score": score,
            "Reasons": ", ".join(reasons),
            "Triggered": ";".join(triggered)
        })
    df = pd.DataFrame(data)
    return df, rule_counts

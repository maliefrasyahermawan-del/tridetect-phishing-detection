"""Tridetect Streamlit Dashboard."""

import sys
from pathlib import Path

# Ensure tridetect package is importable when running from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

st.set_page_config(
    page_title="Tridetect — Phishing Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

from tridetect.shared.db import get_recent_classifications, get_stats, init_db

init_db()

# ── Sidebar ──────────────────────────────────────────────────────────────────
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("Tridetect")
st.sidebar.caption("Tri-vector Phishing Detection System")
st.sidebar.markdown("---")
page = st.sidebar.radio(
    "Module",
    ["🌐 Web Phishing", "📱 SMS / Smishing", "📊 Statistics", "ℹ️ About"],
)

# ── Helper ────────────────────────────────────────────────────────────────────
def label_badge(label: str) -> str:
    colors = {"safe": "🟢", "suspicious": "🟡", "malicious": "🔴"}
    return f"{colors.get(label, '⚪')} **{label.upper()}**"


# ── Page: Web Phishing ────────────────────────────────────────────────────────
if page == "🌐 Web Phishing":
    st.title("🌐 Web Phishing Detection")
    st.markdown(
        "Analyse a URL for phishing indicators: lexical features, brand typosquatting, SSL anomalies."
    )

    url = st.text_input("Enter URL to analyse", placeholder="https://example.com")
    col1, col2 = st.columns(2)
    check_ssl = col1.checkbox("Check SSL certificate", value=True)
    check_brand = col2.checkbox("Check brand typosquat", value=True)

    if st.button("Analyse URL", type="primary"):
        if not url.strip():
            st.error("Please enter a URL.")
        else:
            with st.spinner("Analysing..."):
                try:
                    from tridetect.modules.web_phishing.classifier import WebPhishingClassifier
                    clf = WebPhishingClassifier()
                    result = clf.classify(url.strip(), check_ssl=check_ssl, check_brand=check_brand)
                except Exception as exc:
                    st.error(f"Error: {exc}")
                    result = None

            if result:
                st.markdown(f"### Result: {label_badge(result['label'])}")
                st.metric("Confidence", f"{result['confidence']:.1%}")

                if result.get("brand_match"):
                    st.warning(f"⚠️ Possible typosquat of brand: **{result['brand_match']}**")

                ssl_valid = result.get("ssl_valid")
                if ssl_valid is True:
                    st.success("✅ SSL certificate valid")
                elif ssl_valid is False:
                    st.error("❌ SSL anomaly detected")

                if result.get("reasons"):
                    with st.expander("Detection reasons", expanded=True):
                        for r in result["reasons"]:
                            st.markdown(f"- {r}")

# ── Page: Smishing ─────────────────────────────────────────────────────────
elif page == "📱 SMS / Smishing":
    st.title("📱 SMS / Smishing Detection")
    st.markdown(
        "Analyse an SMS or WhatsApp message for Indonesian phishing patterns, urgency signals, and suspicious URLs."
    )

    sms_text = st.text_area(
        "SMS / Message text",
        placeholder='e.g. "AKUN GOPAY ANDA AKAN DIBEKUKAN. Verifikasi sekarang: bit.ly/xxx"',
        height=120,
    )
    sender = st.text_input("Sender number (optional)", placeholder="+62812...")

    if st.button("Analyse Message", type="primary"):
        if not sms_text.strip():
            st.error("Please enter a message.")
        else:
            with st.spinner("Analysing..."):
                try:
                    from tridetect.modules.smishing.classifier import SmishingClassifier
                    clf = SmishingClassifier()
                    result = clf.classify(sms_text.strip(), sender_number=sender or None)
                except Exception as exc:
                    st.error(f"Error: {exc}")
                    result = None

            if result:
                st.markdown(f"### Result: {label_badge(result['label'])}")

                col1, col2 = st.columns(2)
                col1.metric("Confidence", f"{result['confidence']:.1%}")
                col2.metric("Urgency Score", f"{result.get('urgency_score', 0)}/100")

                if result.get("urls_found"):
                    st.warning(f"⚠️ URLs detected: `{'`, `'.join(result['urls_found'][:5])}`")

                sender_rep = result.get("sender_reputation")
                if sender_rep:
                    st.info(f"Sender type: **{sender_rep}**")

                if result.get("reasons"):
                    with st.expander("Detection reasons", expanded=True):
                        for r in result["reasons"]:
                            st.markdown(f"- {r}")

# ── Page: Statistics ──────────────────────────────────────────────────────────
elif page == "📊 Statistics":
    st.title("📊 Detection Statistics")

    try:
        import pandas as pd

        stats = get_stats()
        recent = get_recent_classifications(limit=200)

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Classifications", stats.get("total", 0))

        by_label = stats.get("by_label", {})
        col2.metric("Malicious detected", by_label.get("malicious", 0))
        col3.metric("Safe / Clean", by_label.get("safe", 0))

        if recent:
            df = pd.DataFrame(recent)
            df["timestamp"] = pd.to_datetime(df["timestamp"])

            st.markdown("### Recent Classifications")
            st.dataframe(
                df[["timestamp", "module", "label", "confidence", "latency_ms"]].head(50),
                use_container_width=True,
            )

            st.markdown("### Label Distribution")
            label_counts = df["label"].value_counts()
            st.bar_chart(label_counts)

            st.markdown("### Module Distribution")
            module_counts = df["module"].value_counts()
            st.bar_chart(module_counts)
        else:
            st.info("No classification history yet. Analyse some URLs or messages first.")
    except Exception as exc:
        st.error(f"Could not load statistics: {exc}")

# ── Page: About ───────────────────────────────────────────────────────────────
elif page == "ℹ️ About":
    st.title("ℹ️ About Tridetect")
    st.markdown(
        """
## Tri-vector Phishing Detection System

**Tridetect** protects users from three modern phishing attack vectors:

| Module | Status | Technology |
|--------|--------|-----------|
| 🌐 Web Phishing | ✅ Active | RF + XGBoost, 25+ lexical features, SSL check, brand typosquat |
| 📱 Smishing | ✅ Active | IndoBERT fine-tuned, urgency scorer, sender reputation |
| 🎤 Vishing | 🔜 Phase 2 | Whisper STT + transcript classification |

## Architecture

```
POST /v1/classify/web  →  WebPhishingClassifier
POST /v1/classify/sms  →  SmishingClassifier
POST /v1/classify/voice →  501 (Phase 2 stub)
```

## Ethical Considerations

- Dataset: Synthetic Indonesian SMS samples — no real user data
- False positives: Rule-based fallback may flag aggressive but legitimate promos
- Privacy: No SMS content stored in plain text — only hash fingerprint logged
- Usage: Intended for defensive cybersecurity purposes only

## Roadmap

- **Phase 2**: Vishing module with Whisper STT
- **Phase 3**: Browser extension (Manifest V3)
- **Phase 4**: Mobile companion app (Flutter)
- **Phase 5**: Voice clone / deepfake detection

---
*MBC Telkom University Cybersecurity Lab*
        """
    )

# SOC Causal Alert Correlation & Root-Cause Intelligence

A system for correlating security alerts from multiple sources, identifying root causes, and recommending minimal-impact response actions.

## Problem Statement

Security Operations Centers (SOCs) face alert fatigue due to high volumes of technically correct but unrelated alerts. This system reconstructs causal incidents by:
1. Normalizing alerts from diverse sources into a common schema
2. Building entity-alert graphs to represent relationships
3. Clustering related alerts into incidents
4. Identifying root causes using temporal, structural, and technique-based scoring
5. Recommending precisely scoped response actions

## Architecture

```
soc-causal-correlation/
├── app.py                  # Streamlit entrypoint
├── config.py               # Configuration constants
├── schema.py               # Pydantic data models
├── ingestion/              # Alert intake and normalization
│   ├── text_input.py       # Text parsing
│   ├── llm_normalizer.py   # Claude API normalization
│   └── validators.py       # Data validation
├── graph/                  # Graph construction and analysis
│   ├── build_graph.py      # Alert-entity graph building
│   ├── time_pruning.py     # Time-based edge pruning
│   └── clustering.py       # Incident detection algorithms
├── analysis/               # Root cause and response analysis
│   ├── root_cause.py       # Root cause identification
│   └── response_recommender.py # Response recommendations
├── evaluation/             # Metrics and evaluation
│   └── metrics.py          # Performance measurement
├── viz/                    # Visualization
│   └── graph_render.py     # Graph visualization
├── data/                   # Data storage
│   ├── raw/                # Raw datasets
│   └── processed/          # Processed data
├── tests/                  # Unit tests
├── notebooks/              # Exploratory analysis
└── requirements.txt        # Python dependencies
```

## Key Features

- **Multi-source Alert Normalization**: Handles alerts from identity platforms, EDR, firewalls, cloud services, etc.
- **Entity Resolution**: Links related alerts through shared users, hosts, IPs, and other entities
- **Temporal Correlation**: connects alerts based on time proximity and causal plausibility
- **Attack Chain Analysis**: Uses MITRE ATT&CK framework to understand attack progression
- **Root Cause Scoring**: Combines temporal, structural, and technique-based factors
- **Response Recommendation**: Suggests minimally disruptive actions based on incident scope
- **Interactive Visualization**: PyVis-based graph exploration of incidents
- **Comprehensive Metrics**: Measures compression ratio, precision, accuracy, and more

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd soc-causal-correlation

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env to add your ANTHROPIC_API_KEY
```

## Usage

### As a Library

```python
from pipeline import alerts_from_text, analyze_alerts

alerts = alerts_from_text(raw_alert_text)
result = analyze_alerts(alerts)
```

### With Streamlit UI

```bash
streamlit run app.py
```

## Data Requirements

The system requires alert data in any text format. The ingestion pipeline will:
1. Parse text into alert chunks
2. Use Claude API to normalize text into structured alerts
3. Validate and enhance the normalized data

For best results, provide alerts with:
- Timestamps
- Source product identification
- Alert descriptions
- Entities (users, hosts, IPs, etc.)
- Severity indicators

## Evaluation Metrics

The system measures effectiveness through:
- **Alert Compression Ratio**: Reduction in alert volume
- **Incident Precision**: Accuracy of incident grouping
- **Root Cause Top-K Accuracy**: Ability to identify true root causes
- **False Suppression Rate**: Avoidance of over-merging incidents
- **Mean Time to Contain**: Speed of detection to action recommendation

## Project Structure

Each module follows a clear separation of concerns:
- `ingestion`: Converts raw alerts to structured format
- `graph`: Builds and analyzes alert-entity relationships
- `analysis`: Performs root cause identification and response recommendations
- `evaluation`: Measures system performance
- `viz`: Provides visualization capabilities
- `schema`: Defines data contracts between components

## Current scope

This is a local MVP. It accepts pasted timestamped alert text and includes an
offline, rule-based normalizer so the demo and Streamlit app work without API
credentials. The optional Claude normalizer can be used by callers that set
`ANTHROPIC_API_KEY`. It does not connect to production SIEMs, persist incident
data, or automatically execute containment actions.

## Future Enhancements

- Integration with actual SIEM products via APIs
- Online learning for adaptive correlation thresholds
- User feedback loop for continuous improvement
- Advanced causal modeling using DoWhy or Bayesian networks
- Automated response playbook generation
- Real-time streaming alert processing

## License

MIT License - see LICENSE file for details.

## Acknowledgments

Built for the Microsoft Innovation Club, VIT Chennai hackathon.

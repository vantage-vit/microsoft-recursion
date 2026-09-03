# SOC Causal Correlation - Reports & Documentation

This folder contains reports, guides, and configuration documentation for the SOC Causal Correlation system, designed to help organizations of all sizes understand and effectively use the system.

## Contents

### 1. Small Business Guidance
- [`small_business_guide.md`](./small_business_guide.md): Non-technical overview for small business owners, managers, and employees
- [`security_recommendations.md`](./security_recommendations.md): Detailed recommendations for improving alert management and security posture

### 2. Technical Configuration & Persistence
- [`alert_persistence_config.md`](./alert_persistence_config.md): Guide on how to save input alert fields and analysis results for audit, compliance, and ongoing improvement

### 3. Source
These documents were created based on analysis of the SOC Causal Correlation system, particularly referencing the video demonstration:
- `"C:\Users\Adhvai\Videos\Captures\SOC Causal Correlation - Brave 2026-09-03 21-41-57.mp4"`

## How to Use These Documents

### For Small Business Owners/Managers:
Start with [`small_business_guide.md`](./small_business_guide.md) to understand what the system does and why it matters in non-technical terms.

### For IT/Security Teams:
1. Review [`security_recommendations.md`](./security_recommendations.md) for actionable improvements to your alert management and security processes
2. Implement [`alert_persistence_config.md`](./alert_persistence_config.md) to save alert data for compliance, auditing, and continuous improvement

### For Compliance/Audit Functions:
Use the alert persistence guidance to establish a defensible archive of security monitoring activities.

## Related Files in Main Repository

The core SOC Causal Correlation system is located in:
- `../soc-causal-correlation/` - Main application code
- Key files to review:
  - `app.py` - Streamlit interface
  - `pipeline.py` - Core analysis workflow
  - `analysis/response_recommender.py` - Response recommendation logic
  - `config.py` - Configuration settings

## Last Updated
September 2026

## Disclaimer
These documents are provided as guidance based on the capabilities demonstrated by the SOC Causal Correlation system. Organizations should adapt recommendations to their specific risk profiles, regulatory requirements, and operational contexts.
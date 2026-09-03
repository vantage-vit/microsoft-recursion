"""
Metrics: compression ratio, root-cause top-k accuracy, false-suppression rate
"""

from typing import List, Dict, Any, Tuple, Set
try:
    # Try relative imports (when used as package)
    from ..schema import Incident, Alert
except ImportError:
    # Fall back to absolute imports (when run directly)
    from schema import Incident, Alert
import numpy as np
from collections import defaultdict

class SecurityMetrics:
    def __init__(self):
        pass

    def calculate_alert_compression_ratio(self, total_alerts: int, incidents: List[Incident]) -> float:
        """
        Calculate alert compression ratio = raw alerts / incidents produced

        Args:
            total_alerts: Total number of input alerts
            incidents: List of identified incidents

        Returns:
            Compression ratio (higher = better compression)
        """
        if len(incidents) == 0:
            return float('inf') if total_alerts > 0 else 0.0

        return total_alerts / len(incidents)

    def calculate_incident_precision(self, predicted_incidents: List[Set[str]],
                                   ground_truth_incidents: List[Set[str]]) -> float:
        """
        Calculate incident precision = TP / (TP + FP)

        Args:
            predicted_incidents: List of sets, each set contains alert IDs in a predicted incident
            ground_truth_incidents: List of sets, each set contains alert IDs in a ground truth incident

        Returns:
            Precision score between 0.0 and 1.0
        """
        if len(predicted_incidents) == 0:
            return 0.0

        # Convert to sets of frozensets for comparison
        predicted_sets = {frozenset(incident) for incident in predicted_incidents}
        ground_truth_sets = {frozenset(incident) for incident in ground_truth_incidents}

        # True positives: predicted incidents that match ground truth
        tp = len(predicted_sets & ground_truth_sets)
        # False positives: predicted incidents that don't match ground truth
        fp = len(predicted_sets - ground_truth_sets)

        if tp + fp == 0:
            return 0.0

        return tp / (tp + fp)

    def calculate_root_cause_top_k_accuracy(self, predicted_root_causes: List[Optional[str]],
                                          ground_truth_root_causes: List[Optional[str]],
                                          k: int = 3) -> float:
        """
        Calculate root-cause top-k accuracy = percentage of times true root cause is in top-k predictions

        Args:
            predicted_root_causes: List of predicted root cause alert IDs (or lists of top-k predictions)
            ground_truth_root_causes: List of true root cause alert IDs
            k: Number of top predictions to consider

        Returns:
            Accuracy score between 0.0 and 1.0
        """
        if len(predicted_root_causes) != len(ground_truth_root_causes):
            raise ValueError("Predicted and ground truth lists must have same length")

        correct = 0
        total = len(predicted_root_causes)

        for i in range(total):
            gt_root = ground_truth_root_causes[i]
            pred_root = predicted_root_causes[i]

            # Handle case where predictions are already top-k lists
            if isinstance(pred_root, list):
                top_k_preds = pred_root[:k]
            else:
                # Single prediction - treat as top-1
                top_k_preds = [pred_root] if pred_root is not None else []

            # Check if ground truth is in top-k predictions
            if gt_root is not None and gt_root in top_k_preds:
                correct += 1
            # Special case: both are None (no root cause)
            elif gt_root is None and pred_root is None:
                correct += 1

        return correct / total if total > 0 else 0.0

    def calculate_false_suppression_rate(self, predicted_incidents: List[Set[str]],
                                       ground_truth_incidents: List[Set[str]]) -> float:
        """
        Calculate false-suppression rate = percentage of ground truth incidents incorrectly merged

        Args:
            predicted_incidents: List of sets, each set contains alert IDs in a predicted incident
            ground_truth_incidents: List of sets, each set contains alert IDs in a ground truth incident

        Returns:
            False suppression rate (lower = better)
        """
        if len(ground_truth_incidents) == 0:
            return 0.0

        # Convert to sets of frozensets for comparison
        predicted_sets = [frozenset(incident) for incident in predicted_incidents]
        ground_truth_sets = [frozenset(incident) for incident in ground_truth_incidents]

        false_suppressions = 0

        # For each ground truth incident, check if it's split across multiple predicted incidents
        for gt_incident in ground_truth_sets:
            # Find which predicted incidents contain alerts from this ground truth incident
            containing_predicted = []
            for pred_incident in predicted_sets:
                # If there's any overlap, consider it containing
                if gt_incident & pred_incident:
                    containing_predicted.append(pred_incident)

            # If ground truth incident is spread across multiple predicted incidents, it's a false suppression
            # Actually, false suppression is when we merge incidents that should be separate
            # So we need to check if multiple ground truth incidents are merged into one predicted incident

        # Re-think: False suppression is when we incorrectly merge separate incidents
        # Let's approach this differently

        # For each predicted incident, check if it contains alerts from multiple ground truth incidents
        false_suppressions = 0
        for pred_incident in predicted_sets:
            # Count how many ground truth incidents have overlap with this predicted incident
            overlapping_gt = []
            for gt_incident in ground_truth_sets:
                if pred_incident & gt_incident:  # Non-empty intersection
                    overlapping_gt.append(gt_incident)

            # If this predicted incident contains alerts from 2+ ground truth incidents,
            # and those ground truth incidents are actually separate (no overlap between them),
            # then we've falsely suppressed them
            if len(overlapping_gt) >= 2:
                # Check if the ground truth incidents are actually separate
                actually_separate = True
                for i in range(len(overlapping_gt)):
                    for j in range(i+1, len(overlapping_gt)):
                        if overlapping_gt[i] & overlapping_gt[j]:  # If they overlap, they're not separate
                            actually_separate = False
                            break
                    if not actually_separate:
                        break

                if actually_separate:
                    false_suppressions += 1

        # False suppression rate = false suppressions / total predicted incidents
        if len(predicted_incidents) == 0:
            return 0.0

        return false_suppressions / len(predicted_incidents)

    def calculate_mean_time_to_contain(self, incidents: List[Incident]) -> float:
        """
        Calculate mean time to contain (simulated) = timestamp of root-cause detection to recommended action
        For simulation, we'll use time from first alert to incident detection

        Args:
            incidents: List of Incident objects

        Returns:
            Mean time to contain in hours
        """
        if len(incidents) == 0:
            return 0.0

        times_to_contain = []

        for incident in incidents:
            # For simulation, use time span of the incident as proxy for detection time
            # In real system, this would be time from first alert to when system flags incident
            time_span_hours = getattr(incident, 'time_span_hours', None)
            if time_span_hours is not None:
                times_to_contain.append(time_span_hours)
            else:
                # Try to calculate from time_range
                if hasattr(incident, 'time_range') and incident.time_range:
                    start = incident.time_range.get('start')
                    end = incident.time_range.get('end')
                    if start and end:
                        from datetime import datetime
                        if isinstance(start, str):
                            start = datetime.fromisoformat(start.replace('Z', '+00:00'))
                        if isinstance(end, str):
                            end = datetime.fromisoformat(end.replace('Z', '+00:00'))
                        if start and end:
                            time_span_hours = (end - start).total_seconds() / 3600
                            times_to_contain.append(time_span_hours)

        if not times_to_contain:
            return 0.0

        return np.mean(times_to_contain)

    def calculate_all_metrics(self, total_alerts: int, predicted_incidents: List[Incident],
                          ground_truth_incidents: List[Dict[str, Any]] = None) -> Dict[str, float]:
        """
        Calculate all metrics at once.

        Args:
            total_alerts: Total number of input alerts
            predicted_incidents: List of predicted Incident objects
            ground_truth_incidents: List of ground truth incident dictionaries (optional)

        Returns:
            Dictionary of metric names and values
        """
        metrics = {}

        # Alert compression ratio
        metrics['alert_compression_ratio'] = self.calculate_alert_compression_ratio(
            total_alerts, predicted_incidents)

        # Mean time to contain
        metrics['mean_time_to_contain_hours'] = self.calculate_mean_time_to_contain(predicted_incidents)

        # If we have ground truth, calculate precision-related metrics
        if ground_truth_incidents is not None:
            # Convert predicted incidents to sets of alert IDs
            predicted_sets = []
            for inc in predicted_incidents:
                alert_ids = set(inc.alert_ids) if hasattr(inc, 'alert_ids') else set()
                predicted_sets.append(alert_ids)

            # Convert ground truth incidents to sets of alert IDs
            ground_truth_sets = []
            for inc_dict in ground_truth_incidents:
                alert_ids = set(inc_dict.get('alert_ids', []))
                ground_truth_sets.append(alert_ids)

            # Incident precision
            metrics['incident_precision'] = self.calculate_incident_precision(
                predicted_sets, ground_truth_sets)

            # False suppression rate
            metrics['false_suppression_rate'] = self.calculate_false_suppression_rate(
                predicted_sets, ground_truth_sets)

            # Root cause accuracy (if available)
            pred_root_causes = []
            gt_root_causes = []
            for inc in predicted_incidents:
                pred_root_causes.append(getattr(inc, 'root_cause_alert_id', None))
            for inc_dict in ground_truth_incidents:
                gt_root_causes.append(inc_dict.get('root_cause_alert_id', None))

            if any(r is not None for r in pred_root_causes + gt_root_causes):
                metrics['root_cause_top_1_accuracy'] = self.calculate_root_cause_top_k_accuracy(
                    pred_root_causes, gt_root_causes, k=1)
                metrics['root_cause_top_3_accuracy'] = self.calculate_root_cause_top_k_accuracy(
                    pred_root_causes, gt_root_causes, k=3)

        return metrics

def print_metrics_report(metrics: Dict[str, float]):
    """Print a formatted metrics report."""
    print("SECURITY METRICS REPORT")
    print("=" * 50)
    for metric_name, value in metrics.items():
        if 'ratio' in metric_name or 'rate' in metric_name:
            print(f"{metric_name:30}: {value:.2f}")
        elif 'accuracy' in metric_name:
            print(f"{metric_name:30}: {value:.2%}")
        elif 'time' in metric_name:
            print(f"{metric_name:30}: {value:.2f} hours")
        else:
            print(f"{metric_name:30}: {value:.3f}")
    print("=" * 50)

if __name__ == "__main__":
    # Test the metrics calculator
    metrics = SecurityMetrics()

    # Test compression ratio
    compression = metrics.calculate_alert_compression_ratio(100, [Incident(incident_id="INC-001", alert_ids=["a1","a2"]),
                                                               Incident(incident_id="INC-002", alert_ids=["a3","a4","a5"])])
    print(f"Compression ratio: {compression:.2f}")

    # Test precision
    pred_incidents = [{"a1", "a2", "a3"}, {"a4", "a5"}]
    gt_incidents = [{"a1", "a2"}, {"a3", "a4", "a5"}]
    precision = metrics.calculate_incident_precision(pred_incidents, gt_incidents)
    print(f"Incident precision: {precision:.2%}")

    # Test root cause accuracy
    pred_roots = ["a1", "a4", None, "a2"]
    gt_roots = ["a1", "a4", "a3", "a2"]
    accuracy = metrics.calculate_root_cause_top_k_accuracy(pred_roots, gt_roots, k=1)
    print(f"Root cause top-1 accuracy: {accuracy:.2%}")

    # Test all metrics
    test_incidents = [
        Incident(incident_id="INC-001", alert_ids=["alert1", "alert2"], confidence_score=0.8),
        Incident(incident_id="INC-002", alert_ids=["alert3", "alert4", "alert5"], confidence_score=0.6)
    ]
    all_metrics = metrics.calculate_all_metrics(20, test_incents)
    print("\nAll metrics:")
    print_metrics_report(all_metrics)
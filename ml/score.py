#!/usr/bin/env python3
"""
Anomaly Scoring Module

This module uses trained ML models to score system snapshots for
rootkit detection and anomaly identification.
"""

import os
import json
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import joblib

from features import FeatureExtractor


class RootkitMLScorer:
    """Scores system snapshots using trained ML models."""
    
    def __init__(self, models_dir="models"):
        self.models_dir = Path(models_dir)
        self.feature_extractor = FeatureExtractor()
        self.models = {}
        self.scaler = None
        self.model_metadata = {}
        self.load_latest_models()
    
    def load_latest_models(self):
        """Load the most recent trained models."""
        try:
            # Find latest metadata file
            metadata_files = list(self.models_dir.glob("training_metadata_*.json"))
            if not metadata_files:
                print("Warning: No trained models found. Please train models first.")
                return
            
            latest_metadata = max(metadata_files, key=os.path.getctime)
            
            with open(latest_metadata, 'r') as f:
                self.model_metadata = json.load(f)
            
            # Load models
            for name, path in self.model_metadata.get('models', {}).items():
                if name == 'metadata':
                    continue
                
                if Path(path).exists():
                    self.models[name] = joblib.load(path)
                    print(f"Loaded model: {name}")
                else:
                    print(f"Warning: Model file not found: {path}")
            
            # Load scaler
            scaler_path = self.model_metadata.get('models', {}).get('scaler')
            if scaler_path and Path(scaler_path).exists():
                self.scaler = joblib.load(scaler_path)
                print("Loaded feature scaler")
            
        except Exception as e:
            print(f"Error loading models: {e}")
    
    def score_snapshot(self, snapshot: Dict, 
                      model_names: List[str] = None) -> Dict[str, Any]:
        """Score a system snapshot using trained models."""
        if not self.models:
            raise RuntimeError("No models loaded. Please train models first.")
        
        # Extract features
        features = self.feature_extractor.extract_features(snapshot)
        features = features.reshape(1, -1)  # Reshape for single sample
        
        # Scale features
        if self.scaler is None:
            raise RuntimeError("Feature scaler not loaded.")
        
        features_scaled = self.scaler.transform(features)
        
        # Score with specified models or all models
        if model_names is None:
            model_names = list(self.models.keys())
        
        scores = {}
        
        for model_name in model_names:
            if model_name not in self.models:
                print(f"Warning: Model '{model_name}' not found")
                continue
            
            model = self.models[model_name]
            score_result = self._score_with_model(model, features_scaled, model_name)
            scores[model_name] = score_result
        
        # Calculate ensemble score
        if len(scores) > 1:
            scores['ensemble'] = self._calculate_ensemble_score(scores)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'feature_vector': features.tolist()[0],
            'scores': scores,
            'model_metadata': self.model_metadata
        }
    
    def _score_with_model(self, model: Any, features: np.ndarray, 
                         model_name: str) -> Dict[str, Any]:
        """Score features with a specific model."""
        result = {'model_name': model_name}
        
        try:
            if hasattr(model, 'predict_proba'):
                # Supervised model
                probabilities = model.predict_proba(features)
                prediction = model.predict(features)
                
                result.update({
                    'type': 'supervised',
                    'prediction': int(prediction[0]),
                    'probability': float(probabilities[0][1]),  # Probability of being malicious
                    'confidence': float(max(probabilities[0]))
                })
            
            elif hasattr(model, 'decision_function'):
                # Unsupervised model
                decision_scores = model.decision_function(features)
                prediction = model.predict(features)
                
                # Normalize decision scores to [0, 1]
                normalized_score = self._normalize_decision_score(decision_scores[0])
                
                result.update({
                    'type': 'unsupervised',
                    'prediction': int(prediction[0]),
                    'anomaly_score': float(decision_scores[0]),
                    'normalized_score': normalized_score,
                    'is_anomaly': prediction[0] == -1
                })
            
            elif hasattr(model, 'labels_'):
                # Clustering model (DBSCAN)
                # For DBSCAN, we need to predict cluster membership
                # This is a simplified approach
                result.update({
                    'type': 'clustering',
                    'cluster_id': 'unknown',
                    'is_outlier': True  # Assume outlier for now
                })
            
            else:
                # Ensemble model
                if isinstance(model, dict) and 'models' in model:
                    ensemble_result = self._score_ensemble_model(model, features)
                    result.update(ensemble_result)
                else:
                    result.update({
                        'type': 'unknown',
                        'error': 'Unknown model type'
                    })
        
        except Exception as e:
            result.update({
                'type': 'error',
                'error': str(e)
            })
        
        return result
    
    def _score_ensemble_model(self, ensemble_model: Dict, features: np.ndarray) -> Dict[str, Any]:
        """Score with ensemble model."""
        try:
            models = ensemble_model.get('models', [])
            scores = []
            
            for name, model in models:
                if hasattr(model, 'predict_proba'):
                    prob = model.predict_proba(features)[0][1]
                    scores.append(prob)
                elif hasattr(model, 'decision_function'):
                    score = model.decision_function(features)[0]
                    normalized_score = self._normalize_decision_score(score)
                    scores.append(normalized_score)
            
            if scores:
                ensemble_score = np.mean(scores)
                ensemble_prediction = 1 if ensemble_score > 0.5 else 0
                
                return {
                    'type': 'ensemble',
                    'prediction': ensemble_prediction,
                    'ensemble_score': float(ensemble_score),
                    'individual_scores': [float(s) for s in scores],
                    'confidence': float(abs(ensemble_score - 0.5) * 2)
                }
            else:
                return {
                    'type': 'ensemble',
                    'error': 'No valid model scores'
                }
        
        except Exception as e:
            return {
                'type': 'ensemble',
                'error': str(e)
            }
    
    def _normalize_decision_score(self, score: float) -> float:
        """Normalize decision function scores to [0, 1] range."""
        # Simple normalization - in practice, you might want to use
        # historical data to determine proper normalization parameters
        return 1.0 / (1.0 + np.exp(-score))
    
    def _calculate_ensemble_score(self, individual_scores: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate ensemble score from individual model scores."""
        try:
            # Extract scores from different model types
            supervised_scores = []
            unsupervised_scores = []
            
            for model_name, score_data in individual_scores.items():
                if score_data.get('type') == 'supervised':
                    supervised_scores.append(score_data.get('probability', 0))
                elif score_data.get('type') == 'unsupervised':
                    unsupervised_scores.append(score_data.get('normalized_score', 0))
            
            # Calculate ensemble score
            all_scores = supervised_scores + unsupervised_scores
            if all_scores:
                ensemble_score = np.mean(all_scores)
                ensemble_prediction = 1 if ensemble_score > 0.5 else 0
                
                return {
                    'type': 'ensemble',
                    'prediction': ensemble_prediction,
                    'ensemble_score': float(ensemble_score),
                    'supervised_contributions': len(supervised_scores),
                    'unsupervised_contributions': len(unsupervised_scores),
                    'confidence': float(abs(ensemble_score - 0.5) * 2)
                }
            else:
                return {
                    'type': 'ensemble',
                    'error': 'No valid scores to ensemble'
                }
        
        except Exception as e:
            return {
                'type': 'ensemble',
                'error': str(e)
            }
    
    def batch_score_snapshots(self, snapshot_files: List[str]) -> List[Dict[str, Any]]:
        """Score multiple snapshots in batch."""
        results = []
        
        for snapshot_file in snapshot_files:
            try:
                with open(snapshot_file, 'r') as f:
                    snapshot = json.load(f)
                
                score_result = self.score_snapshot(snapshot)
                score_result['snapshot_file'] = snapshot_file
                results.append(score_result)
                
            except Exception as e:
                results.append({
                    'snapshot_file': snapshot_file,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        return results
    
    def generate_alert_report(self, scoring_results: Dict[str, Any], 
                            threshold: float = 0.7) -> Dict[str, Any]:
        """Generate an alert report based on scoring results."""
        scores = scoring_results.get('scores', {})
        
        # Determine overall threat level
        threat_level = 'low'
        alert_triggered = False
        
        # Check ensemble score if available
        if 'ensemble' in scores:
            ensemble_score = scores['ensemble'].get('ensemble_score', 0)
            if ensemble_score > threshold:
                alert_triggered = True
                if ensemble_score > 0.9:
                    threat_level = 'critical'
                elif ensemble_score > 0.8:
                    threat_level = 'high'
                else:
                    threat_level = 'medium'
        
        # Check individual model scores
        model_alerts = []
        for model_name, score_data in scores.items():
            if model_name == 'ensemble':
                continue
            
            if score_data.get('type') == 'supervised':
                prob = score_data.get('probability', 0)
                if prob > threshold:
                    model_alerts.append({
                        'model': model_name,
                        'type': 'supervised',
                        'score': prob,
                        'prediction': score_data.get('prediction', 0)
                    })
            
            elif score_data.get('type') == 'unsupervised':
                is_anomaly = score_data.get('is_anomaly', False)
                normalized_score = score_data.get('normalized_score', 0)
                if is_anomaly or normalized_score > threshold:
                    model_alerts.append({
                        'model': model_name,
                        'type': 'unsupervised',
                        'score': normalized_score,
                        'is_anomaly': is_anomaly
                    })
        
        return {
            'timestamp': datetime.now().isoformat(),
            'alert_triggered': alert_triggered,
            'threat_level': threat_level,
            'ensemble_score': scores.get('ensemble', {}).get('ensemble_score', 0),
            'model_alerts': model_alerts,
            'threshold_used': threshold,
            'total_models': len(scores),
            'alerting_models': len(model_alerts)
        }
    
    def save_scoring_results(self, results: Dict[str, Any], 
                           output_dir: str = "scoring_results") -> str:
        """Save scoring results to file."""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scoring_results_{timestamp}.json"
        filepath = output_path / filename
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        return str(filepath)
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models."""
        return {
            'models_loaded': len(self.models),
            'model_names': list(self.models.keys()),
            'feature_count': len(self.feature_extractor.get_feature_names()),
            'scaler_loaded': self.scaler is not None,
            'metadata': self.model_metadata
        }


def main():
    """Main function for scoring snapshots."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Score System Snapshots for Rootkit Detection")
    parser.add_argument("--snapshot", help="Path to snapshot JSON file")
    parser.add_argument("--snapshots-dir", help="Directory containing snapshot files")
    parser.add_argument("--models-dir", default="models",
                       help="Directory containing trained models")
    parser.add_argument("--output", help="Output file for scoring results")
    parser.add_argument("--threshold", type=float, default=0.7,
                       help="Alert threshold (0.0-1.0)")
    parser.add_argument("--model", help="Specific model to use for scoring")
    parser.add_argument("--info", action="store_true",
                       help="Show information about loaded models")
    
    args = parser.parse_args()
    
    scorer = RootkitMLScorer(args.models_dir)
    
    if args.info:
        info = scorer.get_model_info()
        print("Model Information:")
        print("-" * 30)
        print(f"Models loaded: {info['models_loaded']}")
        print(f"Model names: {', '.join(info['model_names'])}")
        print(f"Feature count: {info['feature_count']}")
        print(f"Scaler loaded: {info['scaler_loaded']}")
        return
    
    if not scorer.models:
        print("Error: No models loaded. Please train models first.")
        return
    
    # Score single snapshot
    if args.snapshot:
        try:
            with open(args.snapshot, 'r') as f:
                snapshot = json.load(f)
            
            print(f"Scoring snapshot: {args.snapshot}")
            results = scorer.score_snapshot(snapshot)
            
            # Generate alert report
            alert_report = scorer.generate_alert_report(results, args.threshold)
            
            print("\nScoring Results:")
            print("-" * 50)
            print(f"Alert Triggered: {alert_report['alert_triggered']}")
            print(f"Threat Level: {alert_report['threat_level']}")
            print(f"Ensemble Score: {alert_report['ensemble_score']:.4f}")
            print(f"Threshold Used: {alert_report['threshold_used']}")
            
            if alert_report['model_alerts']:
                print("\nModel Alerts:")
                for alert in alert_report['model_alerts']:
                    print(f"  {alert['model']}: {alert['score']:.4f} ({alert['type']})")
            
            # Save results if requested
            if args.output:
                output_data = {
                    'scoring_results': results,
                    'alert_report': alert_report
                }
                
                with open(args.output, 'w') as f:
                    json.dump(output_data, f, indent=2)
                
                print(f"\nResults saved to: {args.output}")
        
        except FileNotFoundError:
            print(f"Error: Snapshot file '{args.snapshot}' not found")
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in snapshot file '{args.snapshot}'")
    
    # Score multiple snapshots
    elif args.snapshots_dir:
        snapshot_dir = Path(args.snapshots_dir)
        snapshot_files = list(snapshot_dir.glob("*.json"))
        
        if not snapshot_files:
            print(f"No JSON files found in {args.snapshots_dir}")
            return
        
        print(f"Scoring {len(snapshot_files)} snapshots...")
        results = scorer.batch_score_snapshots([str(f) for f in snapshot_files])
        
        # Generate summary
        alerts_triggered = 0
        high_threat_count = 0
        
        for result in results:
            if 'error' not in result:
                alert_report = scorer.generate_alert_report(result, args.threshold)
                if alert_report['alert_triggered']:
                    alerts_triggered += 1
                if alert_report['threat_level'] in ['high', 'critical']:
                    high_threat_count += 1
        
        print(f"\nBatch Scoring Summary:")
        print(f"Total snapshots: {len(snapshot_files)}")
        print(f"Alerts triggered: {alerts_triggered}")
        print(f"High threat alerts: {high_threat_count}")
        
        # Save batch results
        if args.output:
            batch_results = {
                'batch_summary': {
                    'total_snapshots': len(snapshot_files),
                    'alerts_triggered': alerts_triggered,
                    'high_threat_count': high_threat_count,
                    'threshold_used': args.threshold
                },
                'individual_results': results
            }
            
            with open(args.output, 'w') as f:
                json.dump(batch_results, f, indent=2)
            
            print(f"Batch results saved to: {args.output}")
    
    else:
        print("Error: Please specify either --snapshot or --snapshots-dir")
        parser.print_help()


if __name__ == "__main__":
    main()

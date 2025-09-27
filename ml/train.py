#!/usr/bin/env python3
"""
Machine Learning Training Module

This module trains machine learning models for rootkit detection
using features extracted from system snapshots.
"""

import os
import json
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Any
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
import joblib

from features import FeatureExtractor


class RootkitMLTrainer:
    """Trains ML models for rootkit detection."""
    
    def __init__(self, models_dir="models", data_dir="data"):
        self.models_dir = Path(models_dir)
        self.data_dir = Path(data_dir)
        self.models_dir.mkdir(exist_ok=True)
        self.data_dir.mkdir(exist_ok=True)
        
        self.scaler = StandardScaler()
        self.feature_extractor = FeatureExtractor()
        self.models = {}
        self.training_history = {}
    
    def prepare_training_data(self, clean_snapshots: List[str], 
                            malicious_snapshots: List[str] = None) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data from snapshot files."""
        print("Preparing training data...")
        
        features_list = []
        labels_list = []
        
        # Process clean snapshots (label 0)
        print(f"Processing {len(clean_snapshots)} clean snapshots...")
        for snapshot_file in clean_snapshots:
            try:
                with open(snapshot_file, 'r') as f:
                    snapshot = json.load(f)
                
                features = self.feature_extractor.extract_features(snapshot)
                features_list.append(features)
                labels_list.append(0)  # Clean
                
            except (FileNotFoundError, json.JSONDecodeError) as e:
                print(f"Error processing {snapshot_file}: {e}")
                continue
        
        # Process malicious snapshots if provided (label 1)
        if malicious_snapshots:
            print(f"Processing {len(malicious_snapshots)} malicious snapshots...")
            for snapshot_file in malicious_snapshots:
                try:
                    with open(snapshot_file, 'r') as f:
                        snapshot = json.load(f)
                    
                    features = self.feature_extractor.extract_features(snapshot)
                    features_list.append(features)
                    labels_list.append(1)  # Malicious
                    
                except (FileNotFoundError, json.JSONDecodeError) as e:
                    print(f"Error processing {snapshot_file}: {e}")
                    continue
        
        if not features_list:
            raise ValueError("No valid snapshots found for training")
        
        X = np.array(features_list)
        y = np.array(labels_list)
        
        print(f"Training data prepared: {X.shape[0]} samples, {X.shape[1]} features")
        print(f"Clean samples: {np.sum(y == 0)}")
        print(f"Malicious samples: {np.sum(y == 1)}")
        
        return X, y
    
    def train_anomaly_detection_models(self, X: np.ndarray) -> Dict[str, Any]:
        """Train anomaly detection models for unsupervised learning."""
        print("\nTraining anomaly detection models...")
        
        # Standardize features
        X_scaled = self.scaler.fit_transform(X)
        
        models = {}
        
        # Isolation Forest
        print("Training Isolation Forest...")
        iso_forest = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_estimators=100
        )
        iso_forest.fit(X_scaled)
        models['isolation_forest'] = iso_forest
        
        # One-Class SVM
        print("Training One-Class SVM...")
        oc_svm = OneClassSVM(
            kernel='rbf',
            gamma='scale',
            nu=0.1  # Expect 10% anomalies
        )
        oc_svm.fit(X_scaled)
        models['one_class_svm'] = oc_svm
        
        # DBSCAN Clustering
        print("Training DBSCAN...")
        dbscan = DBSCAN(
            eps=0.5,
            min_samples=5
        )
        dbscan.fit(X_scaled)
        models['dbscan'] = dbscan
        
        self.models.update(models)
        return models
    
    def train_supervised_models(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Train supervised classification models."""
        print("\nTraining supervised models...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Standardize features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        models = {}
        
        # Random Forest Classifier
        print("Training Random Forest...")
        rf_params = {
            'n_estimators': [50, 100, 200],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5, 10]
        }
        
        rf = RandomForestClassifier(random_state=42)
        rf_grid = GridSearchCV(rf, rf_params, cv=5, scoring='f1', n_jobs=-1)
        rf_grid.fit(X_train_scaled, y_train)
        
        models['random_forest'] = rf_grid.best_estimator_
        
        # Evaluate model
        y_pred = rf_grid.predict(X_test_scaled)
        y_pred_proba = rf_grid.predict_proba(X_test_scaled)[:, 1]
        
        print(f"Random Forest Best Parameters: {rf_grid.best_params_}")
        print(f"Random Forest Best Score: {rf_grid.best_score_:.4f}")
        print(f"Random Forest Test AUC: {roc_auc_score(y_test, y_pred_proba):.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        self.models.update(models)
        return models
    
    def train_ensemble_model(self, X: np.ndarray, y: np.ndarray = None) -> Dict[str, Any]:
        """Train ensemble model combining multiple approaches."""
        print("\nTraining ensemble model...")
        
        ensemble_models = {}
        
        if y is not None:
            # Supervised ensemble
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train multiple models
            models = [
                ('rf', RandomForestClassifier(n_estimators=100, random_state=42)),
                ('iso', IsolationForest(contamination=0.1, random_state=42)),
                ('svm', OneClassSVM(kernel='rbf', nu=0.1))
            ]
            
            ensemble_predictions = []
            for name, model in models:
                if hasattr(model, 'fit'):
                    if name == 'rf':
                        model.fit(X_train_scaled, y_train)
                        pred = model.predict_proba(X_test_scaled)[:, 1]
                    else:
                        model.fit(X_train_scaled)
                        pred = model.decision_function(X_test_scaled)
                        pred = (pred - pred.min()) / (pred.max() - pred.min())
                    
                    ensemble_predictions.append(pred)
            
            # Simple ensemble (average predictions)
            ensemble_pred = np.mean(ensemble_predictions, axis=0)
            ensemble_score = roc_auc_score(y_test, ensemble_pred)
            
            print(f"Ensemble AUC Score: {ensemble_score:.4f}")
            
            ensemble_models['ensemble'] = {
                'models': models,
                'score': ensemble_score,
                'predictions': ensemble_pred
            }
        
        else:
            # Unsupervised ensemble
            X_scaled = self.scaler.fit_transform(X)
            
            # Train multiple anomaly detection models
            models = [
                ('iso', IsolationForest(contamination=0.1, random_state=42)),
                ('svm', OneClassSVM(kernel='rbf', nu=0.1)),
                ('dbscan', DBSCAN(eps=0.5, min_samples=5))
            ]
            
            ensemble_scores = []
            for name, model in models:
                model.fit(X_scaled)
                
                if name == 'dbscan':
                    # DBSCAN doesn't have decision_function, use labels
                    labels = model.labels_
                    scores = np.where(labels == -1, 1.0, 0.0)  # -1 is outlier
                else:
                    scores = model.decision_function(X_scaled)
                    scores = (scores - scores.min()) / (scores.max() - scores.min())
                
                ensemble_scores.append(scores)
            
            # Combine scores
            ensemble_score = np.mean(ensemble_scores, axis=0)
            
            ensemble_models['ensemble'] = {
                'models': models,
                'scores': ensemble_score,
                'anomaly_threshold': np.percentile(ensemble_score, 90)
            }
        
        self.models.update(ensemble_models)
        return ensemble_models
    
    def evaluate_models(self, X: np.ndarray, y: np.ndarray = None) -> Dict[str, Dict]:
        """Evaluate trained models."""
        print("\nEvaluating models...")
        
        X_scaled = self.scaler.transform(X)
        evaluation_results = {}
        
        for model_name, model in self.models.items():
            if model_name == 'ensemble':
                continue
            
            print(f"Evaluating {model_name}...")
            
            if hasattr(model, 'predict_proba'):
                # Supervised model
                if y is not None:
                    y_pred = model.predict(X_scaled)
                    y_pred_proba = model.predict_proba(X_scaled)[:, 1]
                    
                    evaluation_results[model_name] = {
                        'auc_score': roc_auc_score(y, y_pred_proba),
                        'predictions': y_pred,
                        'probabilities': y_pred_proba,
                        'type': 'supervised'
                    }
                else:
                    # Use decision function for unsupervised evaluation
                    scores = model.decision_function(X_scaled)
                    evaluation_results[model_name] = {
                        'anomaly_scores': scores,
                        'type': 'supervised_unsupervised'
                    }
            
            elif hasattr(model, 'decision_function'):
                # Unsupervised model
                scores = model.decision_function(X_scaled)
                predictions = model.predict(X_scaled)
                
                evaluation_results[model_name] = {
                    'anomaly_scores': scores,
                    'predictions': predictions,
                    'type': 'unsupervised'
                }
            
            elif hasattr(model, 'labels_'):
                # Clustering model
                labels = model.labels_
                evaluation_results[model_name] = {
                    'cluster_labels': labels,
                    'n_clusters': len(set(labels)) - (1 if -1 in labels else 0),
                    'n_outliers': list(labels).count(-1),
                    'type': 'clustering'
                }
        
        return evaluation_results
    
    def save_models(self, model_name: str = None) -> Dict[str, str]:
        """Save trained models to disk."""
        print(f"\nSaving models...")
        
        saved_models = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save scaler
        scaler_path = self.models_dir / f"scaler_{timestamp}.pkl"
        joblib.dump(self.scaler, scaler_path)
        saved_models['scaler'] = str(scaler_path)
        
        # Save individual models
        for name, model in self.models.items():
            if name == 'ensemble':
                continue
            
            model_path = self.models_dir / f"{name}_{timestamp}.pkl"
            joblib.dump(model, model_path)
            saved_models[name] = str(model_path)
        
        # Save ensemble model
        if 'ensemble' in self.models:
            ensemble_path = self.models_dir / f"ensemble_{timestamp}.pkl"
            joblib.dump(self.models['ensemble'], ensemble_path)
            saved_models['ensemble'] = str(ensemble_path)
        
        # Save training metadata
        metadata = {
            'timestamp': timestamp,
            'feature_extractor': 'FeatureExtractor',
            'models': saved_models,
            'feature_count': len(self.feature_extractor.get_feature_names()),
            'feature_names': self.feature_extractor.get_feature_names()
        }
        
        metadata_path = self.models_dir / f"training_metadata_{timestamp}.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        saved_models['metadata'] = str(metadata_path)
        
        print(f"Models saved to {self.models_dir}")
        for name, path in saved_models.items():
            print(f"  {name}: {path}")
        
        return saved_models
    
    def load_models(self, model_dir: str = None) -> Dict[str, Any]:
        """Load previously trained models."""
        if model_dir:
            models_dir = Path(model_dir)
        else:
            models_dir = self.models_dir
        
        # Find latest metadata file
        metadata_files = list(models_dir.glob("training_metadata_*.json"))
        if not metadata_files:
            raise FileNotFoundError("No training metadata found")
        
        latest_metadata = max(metadata_files, key=os.path.getctime)
        
        with open(latest_metadata, 'r') as f:
            metadata = json.load(f)
        
        # Load models
        loaded_models = {}
        
        for name, path in metadata['models'].items():
            if name == 'metadata':
                continue
            
            if Path(path).exists():
                loaded_models[name] = joblib.load(path)
                print(f"Loaded {name} from {path}")
            else:
                print(f"Warning: Model file not found: {path}")
        
        self.models = loaded_models
        self.scaler = loaded_models.get('scaler', StandardScaler())
        
        return loaded_models
    
    def generate_training_report(self, evaluation_results: Dict) -> str:
        """Generate a comprehensive training report."""
        report = []
        report.append("Rootkit Detection ML Training Report")
        report.append("=" * 50)
        report.append(f"Training Date: {datetime.now().isoformat()}")
        report.append("")
        
        for model_name, results in evaluation_results.items():
            report.append(f"Model: {model_name}")
            report.append("-" * 30)
            report.append(f"Type: {results.get('type', 'unknown')}")
            
            if 'auc_score' in results:
                report.append(f"AUC Score: {results['auc_score']:.4f}")
            
            if 'anomaly_scores' in results:
                scores = results['anomaly_scores']
                report.append(f"Anomaly Score Range: {scores.min():.4f} - {scores.max():.4f}")
                report.append(f"Mean Anomaly Score: {scores.mean():.4f}")
            
            if 'n_clusters' in results:
                report.append(f"Number of Clusters: {results['n_clusters']}")
                report.append(f"Number of Outliers: {results['n_outliers']}")
            
            report.append("")
        
        return "\n".join(report)


def main():
    """Main function for training ML models."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Train ML Models for Rootkit Detection")
    parser.add_argument("--clean-snapshots", nargs="+", required=True,
                       help="Paths to clean snapshot files")
    parser.add_argument("--malicious-snapshots", nargs="+",
                       help="Paths to malicious snapshot files")
    parser.add_argument("--models-dir", default="models",
                       help="Directory to save trained models")
    parser.add_argument("--data-dir", default="data",
                       help="Directory for training data")
    parser.add_argument("--mode", choices=["supervised", "unsupervised", "both"],
                       default="both", help="Training mode")
    parser.add_argument("--load-models", help="Directory to load existing models")
    
    args = parser.parse_args()
    
    trainer = RootkitMLTrainer(args.models_dir, args.data_dir)
    
    # Load existing models if specified
    if args.load_models:
        trainer.load_models(args.load_models)
        print("Existing models loaded successfully")
        return
    
    # Prepare training data
    X, y = trainer.prepare_training_data(
        args.clean_snapshots,
        args.malicious_snapshots
    )
    
    # Train models based on mode
    if args.mode in ["unsupervised", "both"]:
        trainer.train_anomaly_detection_models(X)
    
    if args.mode in ["supervised", "both"] and args.malicious_snapshots:
        trainer.train_supervised_models(X, y)
    
    # Train ensemble model
    trainer.train_ensemble_model(X, y if args.malicious_snapshots else None)
    
    # Evaluate models
    evaluation_results = trainer.evaluate_models(X, y if args.malicious_snapshots else None)
    
    # Generate and save report
    report = trainer.generate_training_report(evaluation_results)
    report_path = trainer.models_dir / f"training_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    with open(report_path, 'w') as f:
        f.write(report)
    
    print("\nTraining Report:")
    print(report)
    print(f"\nReport saved to: {report_path}")
    
    # Save models
    saved_models = trainer.save_models()
    
    print("\nTraining completed successfully!")
    print("Models saved:")
    for name, path in saved_models.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    main()

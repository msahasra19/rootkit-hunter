#!/usr/bin/env python3
"""
Detection Rules Engine

This module implements rule-based detection for rootkits and malicious
activities based on system state analysis.
"""

import os
import re
import json
import yaml
from pathlib import Path
from typing import Dict, List, Any, Tuple
from datetime import datetime


class DetectionRule:
    """Represents a single detection rule."""
    
    def __init__(self, name: str, description: str, severity: str, 
                 conditions: List[Dict], actions: List[str] = None):
        self.name = name
        self.description = description
        self.severity = severity  # low, medium, high, critical
        self.conditions = conditions
        self.actions = actions or []
        self.enabled = True
    
    def evaluate(self, snapshot: Dict) -> Tuple[bool, Dict]:
        """Evaluate the rule against a snapshot."""
        if not self.enabled:
            return False, {}
        
        matches = []
        for condition in self.conditions:
            match = self._evaluate_condition(condition, snapshot)
            if match:
                matches.append(match)
        
        # All conditions must match for rule to trigger
        if len(matches) == len(self.conditions):
            result = {
                "rule": self.name,
                "severity": self.severity,
                "description": self.description,
                "timestamp": datetime.now().isoformat(),
                "matches": matches
            }
            return True, result
        
        return False, {}
    
    def _evaluate_condition(self, condition: Dict, snapshot: Dict) -> Dict:
        """Evaluate a single condition."""
        condition_type = condition.get("type")
        
        if condition_type == "process_name":
            return self._check_process_name(condition, snapshot)
        elif condition_type == "file_hash":
            return self._check_file_hash(condition, snapshot)
        elif condition_type == "network_connection":
            return self._check_network_connection(condition, snapshot)
        elif condition_type == "kernel_module":
            return self._check_kernel_module(condition, snapshot)
        elif condition_type == "file_permission":
            return self._check_file_permission(condition, snapshot)
        elif condition_type == "process_hiding":
            return self._check_process_hiding(condition, snapshot)
        elif condition_type == "system_call_hook":
            return self._check_system_call_hook(condition, snapshot)
        elif condition_type == "memory_pattern":
            return self._check_memory_pattern(condition, snapshot)
        
        return {}
    
    def _check_process_name(self, condition: Dict, snapshot: Dict) -> Dict:
        """Check for suspicious process names."""
        pattern = condition.get("pattern", "")
        processes = snapshot.get("processes", [])
        
        matches = []
        for proc in processes:
            if re.search(pattern, proc.get("name", ""), re.IGNORECASE):
                matches.append({
                    "pid": proc.get("pid"),
                    "name": proc.get("name"),
                    "cmdline": proc.get("cmdline", "")
                })
        
        return {"type": "process_name", "matches": matches} if matches else {}
    
    def _check_file_hash(self, condition: Dict, snapshot: Dict) -> Dict:
        """Check for files with known malicious hashes."""
        malicious_hashes = set(condition.get("hashes", []))
        files = snapshot.get("filesystem", {}).get("critical_files", [])
        
        matches = []
        for file_info in files:
            if "hash" in file_info and file_info["hash"] in malicious_hashes:
                matches.append({
                    "path": file_info["path"],
                    "hash": file_info["hash"]
                })
        
        return {"type": "file_hash", "matches": matches} if matches else {}
    
    def _check_network_connection(self, condition: Dict, snapshot: Dict) -> Dict:
        """Check for suspicious network connections."""
        suspicious_ports = set(condition.get("ports", []))
        suspicious_ips = set(condition.get("ips", []))
        connections = snapshot.get("network", {}).get("connections", [])
        
        matches = []
        for conn in connections:
            if conn.get("raddr"):
                ip, port = conn["raddr"].split(":")
                if port in suspicious_ports or ip in suspicious_ips:
                    matches.append({
                        "local": conn.get("laddr"),
                        "remote": conn["raddr"],
                        "pid": conn.get("pid"),
                        "status": conn.get("status")
                    })
        
        return {"type": "network_connection", "matches": matches} if matches else {}
    
    def _check_kernel_module(self, condition: Dict, snapshot: Dict) -> Dict:
        """Check for suspicious kernel modules."""
        suspicious_modules = set(condition.get("modules", []))
        modules = snapshot.get("kernel_modules", [])
        
        matches = []
        for module in modules:
            if "name" in module and module["name"] in suspicious_modules:
                matches.append({
                    "name": module["name"],
                    "size": module.get("size"),
                    "used_by": module.get("used_by")
                })
        
        return {"type": "kernel_module", "matches": matches} if matches else {}
    
    def _check_file_permission(self, condition: Dict, snapshot: Dict) -> Dict:
        """Check for suspicious file permissions."""
        files = snapshot.get("filesystem", {}).get("critical_files", [])
        
        matches = []
        for file_info in files:
            if "mode" in file_info:
                mode = int(file_info["mode"], 8)
                # Check for world-writable files
                if condition.get("check_world_writable") and (mode & 0o002):
                    matches.append({
                        "path": file_info["path"],
                        "mode": file_info["mode"],
                        "uid": file_info.get("uid"),
                        "gid": file_info.get("gid")
                    })
        
        return {"type": "file_permission", "matches": matches} if matches else {}
    
    def _check_process_hiding(self, condition: Dict, snapshot: Dict) -> Dict:
        """Check for processes that might be hiding."""
        # This is a simplified check - real implementation would be more complex
        processes = snapshot.get("processes", [])
        
        matches = []
        for proc in processes:
            # Check for processes with suspicious names or missing cmdline
            name = proc.get("name", "")
            cmdline = proc.get("cmdline", "")
            
            if condition.get("check_suspicious_names"):
                suspicious_patterns = [r"\.\w+$", r"^\s*$", r"\[.*\]"]
                for pattern in suspicious_patterns:
                    if re.search(pattern, name):
                        matches.append({
                            "pid": proc.get("pid"),
                            "name": name,
                            "cmdline": cmdline,
                            "reason": f"matches pattern: {pattern}"
                        })
                        break
        
        return {"type": "process_hiding", "matches": matches} if matches else {}
    
    def _check_system_call_hook(self, condition: Dict, snapshot: Dict) -> Dict:
        """Check for system call hooks."""
        # This would require more sophisticated analysis
        # For now, we'll check for unusual system call patterns
        symbols = snapshot.get("system_calls", {})
        
        matches = []
        if "error" not in symbols and condition.get("check_symbol_manipulation"):
            # In a real implementation, this would analyze system call tables
            # and compare against known good patterns
            pass
        
        return {"type": "system_call_hook", "matches": matches} if matches else {}
    
    def _check_memory_pattern(self, condition: Dict, snapshot: Dict) -> Dict:
        """Check for suspicious memory patterns."""
        # This would require memory analysis tools
        # For now, we'll check for unusual memory usage
        memory = snapshot.get("memory", {})
        
        matches = []
        if condition.get("check_high_memory_usage"):
            virtual_mem = memory.get("virtual", {})
            if virtual_mem.get("percent", 0) > condition.get("threshold", 90):
                matches.append({
                    "memory_usage_percent": virtual_mem.get("percent"),
                    "total_memory": virtual_mem.get("total"),
                    "used_memory": virtual_mem.get("used")
                })
        
        return {"type": "memory_pattern", "matches": matches} if matches else {}


class RulesEngine:
    """Main rules engine for rootkit detection."""
    
    def __init__(self, rules_dir="rules"):
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(exist_ok=True)
        self.rules = []
        self.load_rules()
    
    def load_rules(self):
        """Load rules from configuration files."""
        # Load default built-in rules
        self._load_default_rules()
        
        # Load custom rules from files
        for rule_file in self.rules_dir.glob("*.yaml"):
            self._load_rule_file(rule_file)
        
        for rule_file in self.rules_dir.glob("*.json"):
            self._load_rule_file(rule_file)
    
    def _load_default_rules(self):
        """Load built-in default rules."""
        default_rules = [
            DetectionRule(
                name="suspicious_process_names",
                description="Detect processes with suspicious names",
                severity="medium",
                conditions=[
                    {
                        "type": "process_name",
                        "pattern": r"(\.so|\.ko|\.dll)$"
                    }
                ]
            ),
            DetectionRule(
                name="world_writable_critical_files",
                description="Detect world-writable critical system files",
                severity="high",
                conditions=[
                    {
                        "type": "file_permission",
                        "check_world_writable": True
                    }
                ]
            ),
            DetectionRule(
                name="suspicious_network_connections",
                description="Detect suspicious network connections",
                severity="medium",
                conditions=[
                    {
                        "type": "network_connection",
                        "ports": ["6666", "31337", "12345"],
                        "ips": []
                    }
                ]
            ),
            DetectionRule(
                name="high_memory_usage",
                description="Detect unusually high memory usage",
                severity="low",
                conditions=[
                    {
                        "type": "memory_pattern",
                        "check_high_memory_usage": True,
                        "threshold": 95
                    }
                ]
            )
        ]
        
        self.rules.extend(default_rules)
    
    def _load_rule_file(self, rule_file: Path):
        """Load rules from a configuration file."""
        try:
            with open(rule_file, 'r') as f:
                if rule_file.suffix == '.yaml':
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
            
            for rule_data in data.get("rules", []):
                rule = DetectionRule(
                    name=rule_data["name"],
                    description=rule_data["description"],
                    severity=rule_data["severity"],
                    conditions=rule_data["conditions"],
                    actions=rule_data.get("actions", [])
                )
                self.rules.append(rule)
                
        except (yaml.YAMLError, json.JSONDecodeError, KeyError) as e:
            print(f"Error loading rule file {rule_file}: {e}")
    
    def evaluate_snapshot(self, snapshot: Dict) -> List[Dict]:
        """Evaluate all rules against a snapshot."""
        results = []
        
        for rule in self.rules:
            triggered, result = rule.evaluate(snapshot)
            if triggered:
                results.append(result)
        
        return results
    
    def add_rule(self, rule: DetectionRule):
        """Add a new rule to the engine."""
        self.rules.append(rule)
    
    def remove_rule(self, rule_name: str):
        """Remove a rule by name."""
        self.rules = [rule for rule in self.rules if rule.name != rule_name]
    
    def enable_rule(self, rule_name: str):
        """Enable a rule by name."""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = True
                break
    
    def disable_rule(self, rule_name: str):
        """Disable a rule by name."""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = False
                break
    
    def list_rules(self) -> List[Dict]:
        """List all loaded rules."""
        return [
            {
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity,
                "enabled": rule.enabled,
                "condition_count": len(rule.conditions)
            }
            for rule in self.rules
        ]


def main():
    """Main function for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Rootkit Detection Rules Engine")
    parser.add_argument("--snapshot", help="Path to snapshot file to analyze")
    parser.add_argument("--list-rules", action="store_true", help="List all loaded rules")
    parser.add_argument("--rules-dir", default="rules", help="Directory containing rule files")
    
    args = parser.parse_args()
    
    engine = RulesEngine(args.rules_dir)
    
    if args.list_rules:
        rules = engine.list_rules()
        print("\nLoaded Rules:")
        print("-" * 80)
        for rule in rules:
            status = "ENABLED" if rule["enabled"] else "DISABLED"
            print(f"Name: {rule['name']}")
            print(f"Description: {rule['description']}")
            print(f"Severity: {rule['severity']}")
            print(f"Status: {status}")
            print(f"Conditions: {rule['condition_count']}")
            print("-" * 80)
    
    if args.snapshot:
        try:
            with open(args.snapshot, 'r') as f:
                snapshot = json.load(f)
            
            results = engine.evaluate_snapshot(snapshot)
            
            if results:
                print(f"\n{len(results)} rule(s) triggered:")
                for result in results:
                    print(f"\nRule: {result['rule']}")
                    print(f"Severity: {result['severity']}")
                    print(f"Description: {result['description']}")
                    print(f"Matches: {len(result['matches'])}")
            else:
                print("No rules triggered.")
                
        except FileNotFoundError:
            print(f"Error: Snapshot file '{args.snapshot}' not found")
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in snapshot file '{args.snapshot}'")


if __name__ == "__main__":
    main()

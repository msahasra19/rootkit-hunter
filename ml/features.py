#!/usr/bin/env python3
"""
Feature Extraction Module

This module extracts features from system snapshots for machine learning
models used in rootkit detection.
"""

import os
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
from pathlib import Path
from datetime import datetime
import hashlib


class FeatureExtractor:
    """Extracts features from system snapshots for ML models."""
    
    def __init__(self):
        self.feature_names = []
        self.feature_stats = {}
    
    def extract_features(self, snapshot: Dict) -> np.ndarray:
        """Extract all features from a system snapshot."""
        features = []
        
        # Process-based features
        features.extend(self._extract_process_features(snapshot))
        
        # File system features
        features.extend(self._extract_filesystem_features(snapshot))
        
        # Network features
        features.extend(self._extract_network_features(snapshot))
        
        # Kernel module features
        features.extend(self._extract_kernel_features(snapshot))
        
        # Memory features
        features.extend(self._extract_memory_features(snapshot))
        
        # System call features
        features.extend(self._extract_system_call_features(snapshot))
        
        # Behavioral features
        features.extend(self._extract_behavioral_features(snapshot))
        
        return np.array(features)
    
    def _extract_process_features(self, snapshot: Dict) -> List[float]:
        """Extract features related to running processes."""
        features = []
        processes = snapshot.get("processes", [])
        
        if not processes:
            return [0.0] * 20  # Return zeros if no process data
        
        # Basic process statistics
        features.append(len(processes))  # Total process count
        
        # Process name analysis
        process_names = [p.get("name", "") for p in processes]
        unique_names = len(set(process_names))
        features.append(unique_names)  # Unique process names
        features.append(unique_names / len(process_names) if processes else 0)  # Name diversity
        
        # Suspicious process name patterns
        suspicious_patterns = [r"\.so$", r"\.ko$", r"\.dll$", r"\[.*\]", r"^\s*$"]
        suspicious_count = 0
        for name in process_names:
            for pattern in suspicious_patterns:
                if pattern == r"\[.*\]":
                    if name.startswith("[") and name.endswith("]"):
                        suspicious_count += 1
                        break
                elif pattern == r"^\s*$":
                    if not name.strip():
                        suspicious_count += 1
                        break
                else:
                    import re
                    if re.search(pattern, name):
                        suspicious_count += 1
                        break
        
        features.append(suspicious_count)
        features.append(suspicious_count / len(processes) if processes else 0)
        
        # Process command line analysis
        cmdlines = [p.get("cmdline", "") for p in processes]
        empty_cmdlines = sum(1 for cmd in cmdlines if not cmd.strip())
        features.append(empty_cmdlines)
        features.append(empty_cmdlines / len(processes) if processes else 0)
        
        # Process path analysis
        paths = [p.get("exe", "") for p in processes if p.get("exe")]
        suspicious_paths = sum(1 for path in paths if self._is_suspicious_path(path))
        features.append(suspicious_paths)
        features.append(suspicious_paths / len(paths) if paths else 0)
        
        # Process age analysis
        current_time = time.time()
        ages = []
        for proc in processes:
            if proc.get("create_time"):
                age = current_time - proc["create_time"]
                ages.append(age)
        
        if ages:
            features.append(np.mean(ages))  # Average process age
            features.append(np.std(ages))   # Process age std deviation
            features.append(min(ages))      # Youngest process
            features.append(max(ages))      # Oldest process
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])
        
        # Process hierarchy analysis
        parent_child_ratio = self._calculate_process_hierarchy(processes)
        features.append(parent_child_ratio)
        
        # Process privilege analysis
        privileged_processes = sum(1 for p in processes if self._is_privileged_process(p))
        features.append(privileged_processes)
        features.append(privileged_processes / len(processes) if processes else 0)
        
        # Process resource usage patterns
        features.extend(self._analyze_process_resources(processes))
        
        return features
    
    def _extract_filesystem_features(self, snapshot: Dict) -> List[float]:
        """Extract features related to file system."""
        features = []
        fs_data = snapshot.get("filesystem", {})
        files = fs_data.get("critical_files", [])
        
        if not files:
            return [0.0] * 15  # Return zeros if no file data
        
        # File count and diversity
        features.append(len(files))
        
        # File permission analysis
        world_writable = 0
        suid_files = 0
        sgid_files = 0
        suspicious_permissions = 0
        
        for file_info in files:
            if "mode" in file_info:
                mode = int(file_info["mode"], 8)
                if mode & 0o002:  # World writable
                    world_writable += 1
                if mode & 0o4000:  # SUID
                    suid_files += 1
                if mode & 0o2000:  # SGID
                    sgid_files += 1
                if self._is_suspicious_permission(mode):
                    suspicious_permissions += 1
        
        features.extend([world_writable, suid_files, sgid_files, suspicious_permissions])
        
        # File ownership analysis
        root_owned = sum(1 for f in files if f.get("uid") == 0)
        features.append(root_owned)
        features.append(root_owned / len(files) if files else 0)
        
        # File modification time analysis
        current_time = time.time()
        recent_modifications = 0
        mod_times = []
        
        for file_info in files:
            if "mtime" in file_info:
                try:
                    mod_time = datetime.fromisoformat(file_info["mtime"]).timestamp()
                    mod_times.append(mod_time)
                    if current_time - mod_time < 3600:  # Modified in last hour
                        recent_modifications += 1
                except (ValueError, TypeError):
                    continue
        
        features.append(recent_modifications)
        features.append(recent_modifications / len(files) if files else 0)
        
        if mod_times:
            features.append(np.std(mod_times))  # Modification time variance
        else:
            features.append(0.0)
        
        # File size analysis
        sizes = [f.get("size", 0) for f in files if f.get("size")]
        if sizes:
            features.append(np.mean(sizes))  # Average file size
            features.append(np.std(sizes))   # File size variance
            features.append(max(sizes))      # Largest file
        else:
            features.extend([0.0, 0.0, 0.0])
        
        # File hash diversity
        hashes = [f.get("hash") for f in files if f.get("hash")]
        unique_hashes = len(set(hashes)) if hashes else 0
        features.append(unique_hashes)
        
        return features
    
    def _extract_network_features(self, snapshot: Dict) -> List[float]:
        """Extract features related to network activity."""
        features = []
        network_data = snapshot.get("network", {})
        connections = network_data.get("connections", [])
        
        # Connection statistics
        features.append(len(connections))
        
        if not connections:
            return features + [0.0] * 20  # Return zeros if no connection data
        
        # Connection type analysis
        tcp_connections = sum(1 for c in connections if c.get("type") == 1)
        udp_connections = sum(1 for c in connections if c.get("type") == 2)
        features.extend([tcp_connections, udp_connections])
        
        # Connection state analysis
        states = [c.get("status") for c in connections if c.get("status")]
        unique_states = len(set(states))
        features.append(unique_states)
        
        # Remote address analysis
        remote_addrs = []
        local_ports = []
        remote_ports = []
        
        for conn in connections:
            if conn.get("raddr"):
                try:
                    ip, port = conn["raddr"].split(":")
                    remote_addrs.append(ip)
                    remote_ports.append(int(port))
                except (ValueError, AttributeError):
                    continue
            
            if conn.get("laddr"):
                try:
                    ip, port = conn["laddr"].split(":")
                    local_ports.append(int(port))
                except (ValueError, AttributeError):
                    continue
        
        # Network diversity
        unique_remote_ips = len(set(remote_addrs)) if remote_addrs else 0
        features.append(unique_remote_ips)
        features.append(unique_remote_ips / len(connections) if connections else 0)
        
        # Port analysis
        unique_local_ports = len(set(local_ports)) if local_ports else 0
        unique_remote_ports = len(set(remote_ports)) if remote_ports else 0
        features.extend([unique_local_ports, unique_remote_ports])
        
        # Suspicious port usage
        suspicious_local_ports = sum(1 for port in local_ports if self._is_suspicious_port(port))
        suspicious_remote_ports = sum(1 for port in remote_ports if self._is_suspicious_port(port))
        features.extend([suspicious_local_ports, suspicious_remote_ports])
        
        # Port range analysis
        if local_ports:
            features.append(max(local_ports) - min(local_ports))  # Local port range
        else:
            features.append(0.0)
        
        if remote_ports:
            features.append(max(remote_ports) - min(remote_ports))  # Remote port range
        else:
            features.append(0.0)
        
        # Connection frequency analysis
        if remote_addrs:
            addr_counts = {}
            for addr in remote_addrs:
                addr_counts[addr] = addr_counts.get(addr, 0) + 1
            
            max_connections_per_addr = max(addr_counts.values()) if addr_counts else 0
            features.append(max_connections_per_addr)
        else:
            features.append(0.0)
        
        # Network interface analysis
        interfaces = network_data.get("interfaces", [])
        features.append(len(interfaces))
        
        # Network I/O statistics
        io_counters = network_data.get("io_counters", {})
        if io_counters:
            features.extend([
                io_counters.get("bytes_sent", 0),
                io_counters.get("bytes_recv", 0),
                io_counters.get("packets_sent", 0),
                io_counters.get("packets_recv", 0)
            ])
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])
        
        return features
    
    def _extract_kernel_features(self, snapshot: Dict) -> List[float]:
        """Extract features related to kernel modules."""
        features = []
        modules = snapshot.get("kernel_modules", [])
        
        # Module statistics
        features.append(len(modules))
        
        if not modules:
            return features + [0.0] * 10  # Return zeros if no module data
        
        # Module size analysis
        sizes = []
        for module in modules:
            if module.get("size"):
                try:
                    sizes.append(int(module["size"]))
                except (ValueError, TypeError):
                    continue
        
        if sizes:
            features.extend([
                np.mean(sizes),  # Average module size
                np.std(sizes),   # Module size variance
                max(sizes),      # Largest module
                min(sizes)       # Smallest module
            ])
        else:
            features.extend([0.0, 0.0, 0.0, 0.0])
        
        # Module usage analysis
        used_modules = sum(1 for m in modules if m.get("used_by") and m.get("used_by") != "-")
        features.append(used_modules)
        features.append(used_modules / len(modules) if modules else 0)
        
        # Suspicious module names
        suspicious_modules = 0
        for module in modules:
            if self._is_suspicious_module(module.get("name", "")):
                suspicious_modules += 1
        
        features.append(suspicious_modules)
        features.append(suspicious_modules / len(modules) if modules else 0)
        
        # Module name patterns
        module_names = [m.get("name", "") for m in modules]
        short_names = sum(1 for name in module_names if len(name) < 5)
        features.append(short_names)
        
        return features
    
    def _extract_memory_features(self, snapshot: Dict) -> List[float]:
        """Extract features related to memory usage."""
        features = []
        memory_data = snapshot.get("memory", {})
        
        # Virtual memory features
        virtual_mem = memory_data.get("virtual", {})
        features.extend([
            virtual_mem.get("total", 0),
            virtual_mem.get("available", 0),
            virtual_mem.get("used", 0),
            virtual_mem.get("free", 0),
            virtual_mem.get("percent", 0)
        ])
        
        # Memory utilization ratios
        if virtual_mem.get("total", 0) > 0:
            features.extend([
                virtual_mem.get("used", 0) / virtual_mem["total"],  # Used ratio
                virtual_mem.get("available", 0) / virtual_mem["total"],  # Available ratio
                virtual_mem.get("free", 0) / virtual_mem["total"]   # Free ratio
            ])
        else:
            features.extend([0.0, 0.0, 0.0])
        
        # Swap memory features
        swap_mem = memory_data.get("swap", {})
        features.extend([
            swap_mem.get("total", 0),
            swap_mem.get("used", 0),
            swap_mem.get("free", 0),
            swap_mem.get("percent", 0)
        ])
        
        # Swap utilization
        if swap_mem.get("total", 0) > 0:
            features.append(swap_mem.get("used", 0) / swap_mem["total"])
        else:
            features.append(0.0)
        
        return features
    
    def _extract_system_call_features(self, snapshot: Dict) -> List[float]:
        """Extract features related to system calls."""
        features = []
        syscall_data = snapshot.get("system_calls", {})
        
        # Symbol count
        symbol_count = syscall_data.get("symbol_count", 0)
        features.append(symbol_count)
        
        # Sample symbols analysis
        sample_symbols = syscall_data.get("sample_symbols", [])
        features.append(len(sample_symbols))
        
        # Symbol pattern analysis
        if sample_symbols:
            # Count different symbol types
            syscall_symbols = sum(1 for s in sample_symbols if "sys_" in s)
            features.append(syscall_symbols)
            features.append(syscall_symbols / len(sample_symbols) if sample_symbols else 0)
        else:
            features.extend([0.0, 0.0])
        
        return features
    
    def _extract_behavioral_features(self, snapshot: Dict) -> List[float]:
        """Extract behavioral features from the snapshot."""
        features = []
        
        # System uptime
        system_info = snapshot.get("system_info", {})
        if system_info.get("boot_time"):
            try:
                boot_time = datetime.fromisoformat(system_info["boot_time"]).timestamp()
                uptime = time.time() - boot_time
                features.append(uptime)
            except (ValueError, TypeError):
                features.append(0.0)
        else:
            features.append(0.0)
        
        # CPU information
        cpu_count = system_info.get("cpu_count", 0)
        features.append(cpu_count)
        
        # Process-to-CPU ratio
        process_count = len(snapshot.get("processes", []))
        if cpu_count > 0:
            features.append(process_count / cpu_count)
        else:
            features.append(0.0)
        
        # Network-to-process ratio
        network_connections = len(snapshot.get("network", {}).get("connections", []))
        if process_count > 0:
            features.append(network_connections / process_count)
        else:
            features.append(0.0)
        
        # File-to-process ratio
        file_count = len(snapshot.get("filesystem", {}).get("critical_files", []))
        if process_count > 0:
            features.append(file_count / process_count)
        else:
            features.append(0.0)
        
        # System complexity metrics
        unique_process_names = len(set(p.get("name", "") for p in snapshot.get("processes", [])))
        features.append(unique_process_names)
        
        unique_file_paths = len(set(f.get("path", "") for f in snapshot.get("filesystem", {}).get("critical_files", [])))
        features.append(unique_file_paths)
        
        return features
    
    def _is_suspicious_path(self, path: str) -> bool:
        """Check if a process path is suspicious."""
        if not path:
            return False
        
        suspicious_patterns = [
            "/tmp/",
            "/dev/shm/",
            "/var/tmp/",
            "/proc/",
            "/sys/",
            ".so",
            ".ko"
        ]
        
        return any(pattern in path for pattern in suspicious_patterns)
    
    def _is_suspicious_permission(self, mode: int) -> bool:
        """Check if file permissions are suspicious."""
        # World-writable system files
        if mode & 0o002:
            return True
        
        # Unusual permission combinations
        if mode & 0o4000 and mode & 0o002:  # SUID and world-writable
            return True
        
        return False
    
    def _is_suspicious_port(self, port: int) -> bool:
        """Check if a port number is suspicious."""
        suspicious_ports = {
            6666, 31337, 12345, 54321, 11111, 22222, 33333, 44444, 55555,
            1234, 4321, 8080, 8888, 9999, 1337, 31337
        }
        
        return port in suspicious_ports
    
    def _is_suspicious_module(self, name: str) -> bool:
        """Check if a kernel module name is suspicious."""
        if not name:
            return False
        
        suspicious_patterns = [
            "hidden", "stealth", "rootkit", "backdoor", "keylog",
            ".so", ".ko", "test", "demo"
        ]
        
        return any(pattern in name.lower() for pattern in suspicious_patterns)
    
    def _calculate_process_hierarchy(self, processes: List[Dict]) -> float:
        """Calculate process hierarchy complexity."""
        # Simplified hierarchy analysis
        # In a real implementation, this would build a process tree
        return len(processes) / 10.0  # Simplified ratio
    
    def _is_privileged_process(self, process: Dict) -> bool:
        """Check if a process is running with elevated privileges."""
        # This would require more detailed process information
        # For now, check for common privileged process names
        privileged_names = ["root", "sudo", "su", "systemd", "init"]
        name = process.get("name", "").lower()
        
        return any(priv_name in name for priv_name in privileged_names)
    
    def _analyze_process_resources(self, processes: List[Dict]) -> List[float]:
        """Analyze process resource usage patterns."""
        # This would require real-time process monitoring
        # For now, return placeholder values
        return [0.0, 0.0, 0.0, 0.0]
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names."""
        if not self.feature_names:
            # Generate feature names based on extraction methods
            self.feature_names = [
                # Process features (20)
                "process_count", "unique_process_names", "name_diversity",
                "suspicious_process_count", "suspicious_process_ratio",
                "empty_cmdlines", "empty_cmdline_ratio",
                "suspicious_paths", "suspicious_path_ratio",
                "avg_process_age", "std_process_age", "min_process_age", "max_process_age",
                "process_hierarchy_ratio", "privileged_processes", "privileged_process_ratio",
                "process_resource_1", "process_resource_2", "process_resource_3", "process_resource_4",
                
                # Filesystem features (15)
                "file_count", "world_writable_files", "suid_files", "sgid_files", "suspicious_permissions",
                "root_owned_files", "root_owned_ratio", "recent_modifications", "recent_modification_ratio",
                "modification_time_variance", "avg_file_size", "file_size_variance", "max_file_size",
                "unique_file_hashes", "file_hash_diversity",
                
                # Network features (20)
                "connection_count", "tcp_connections", "udp_connections", "unique_connection_states",
                "unique_remote_ips", "remote_ip_diversity", "unique_local_ports", "unique_remote_ports",
                "suspicious_local_ports", "suspicious_remote_ports", "local_port_range", "remote_port_range",
                "max_connections_per_addr", "network_interface_count", "bytes_sent", "bytes_received",
                "packets_sent", "packets_received", "network_io_1", "network_io_2",
                
                # Kernel features (10)
                "module_count", "avg_module_size", "module_size_variance", "max_module_size", "min_module_size",
                "used_modules", "used_module_ratio", "suspicious_modules", "suspicious_module_ratio",
                "short_module_names",
                
                # Memory features (10)
                "total_memory", "available_memory", "used_memory", "free_memory", "memory_percent",
                "memory_used_ratio", "memory_available_ratio", "memory_free_ratio",
                "swap_total", "swap_used_ratio",
                
                # System call features (5)
                "symbol_count", "sample_symbol_count", "syscall_symbols", "syscall_symbol_ratio",
                "symbol_analysis_1",
                
                # Behavioral features (10)
                "system_uptime", "cpu_count", "process_cpu_ratio", "network_process_ratio",
                "file_process_ratio", "unique_process_names_behavioral", "unique_file_paths_behavioral",
                "behavioral_1", "behavioral_2", "behavioral_3"
            ]
        
        return self.feature_names


def main():
    """Main function for testing feature extraction."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Feature Extraction for Rootkit Detection")
    parser.add_argument("--snapshot", required=True, help="Path to snapshot JSON file")
    parser.add_argument("--output", help="Path to save extracted features")
    
    args = parser.parse_args()
    
    # Load snapshot
    with open(args.snapshot, 'r') as f:
        snapshot = json.load(f)
    
    # Extract features
    extractor = FeatureExtractor()
    features = extractor.extract_features(snapshot)
    
    print(f"Extracted {len(features)} features")
    print(f"Feature names: {len(extractor.get_feature_names())}")
    
    if args.output:
        # Save features
        feature_data = {
            "timestamp": datetime.now().isoformat(),
            "snapshot_file": args.snapshot,
            "features": features.tolist(),
            "feature_names": extractor.get_feature_names()
        }
        
        with open(args.output, 'w') as f:
            json.dump(feature_data, f, indent=2)
        
        print(f"Features saved to: {args.output}")
    else:
        # Print feature summary
        print("\nFeature Summary:")
        print("-" * 50)
        for i, (name, value) in enumerate(zip(extractor.get_feature_names(), features)):
            print(f"{i+1:3d}. {name:30s}: {value:10.4f}")


if __name__ == "__main__":
    import time
    main()

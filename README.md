# Rootkit Hunter

A comprehensive rootkit detection system that combines system monitoring, baseline comparison, and machine learning for advanced threat detection.

## Features

- **System Monitoring**: Real-time collection of system state and file system snapshots
- **Baseline Comparison**: Detection of changes against known good baselines
- **Machine Learning**: Advanced anomaly detection using ML models
- **Rule-Based Detection**: Customizable detection rules for known threats
- **Docker Support**: Containerized deployment for easy setup

## Project Structure

```
rootkit-hunter/
├── setup.sh              # Setup script for environment
├── docker-compose.yml    # Docker configuration
├── requirements.txt      # Python dependencies
├── collector/            # Data collection and detection
│   ├── snapshot.py       # System snapshot creation
│   ├── create_baseline.py # Baseline generation
│   ├── rules.py          # Detection rules engine
│   ├── forwarder.py      # Data forwarding
│   └── run_detection.sh  # Detection execution script
├── ml/                   # Machine learning components
│   ├── features.py       # Feature extraction
│   ├── train.py          # Model training
│   └── score.py          # Anomaly scoring
└── README.md             # This file
```

## Quick Start

1. **Setup Environment**:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

2. **Using Docker**:
   ```bash
   docker-compose up -d
   ```

3. **Manual Setup**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## Usage

### Creating a Baseline
```bash
cd collector
python create_baseline.py
```

### Running Detection
```bash
cd collector
./run_detection.sh
```

### Training ML Models
```bash
cd ml
python train.py
```

## Configuration

Configuration files and settings can be found in the respective modules. Each component is designed to be modular and configurable.

## Contributing

Please ensure all code follows the existing style and includes appropriate documentation.

## License

[Add your license information here]

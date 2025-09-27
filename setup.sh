#!/bin/bash
set -e

echo "🔄 Updating system..."
sudo apt update && sudo apt upgrade -y

echo "📦 Installing dependencies..."
sudo apt install -y python3 python3-pip docker.io docker-compose git curl netcat-openbsd

echo "🐍 Installing Python libraries (for current user)..."
pip3 install --user psutil scikit-learn pandas joblib requests

# Make sure ~/.local/bin is on PATH for pip --user installs
export PATH=$HOME/.local/bin:$PATH

echo "📂 Creating project directories..."
mkdir -p $HOME/rootkit
# If repo not present, clone (or pull if it exists)
if [ ! -d "$HOME/rootkit/.git" ]; then
  echo "Cloning repo (edit URL in setup.sh if needed)..."
  git clone https://github.com/your-team/rootkit-hunter.git $HOME/rootkit || true
else
  echo "Repo already exists — pulling latest..."
  cd $HOME/rootkit && git pull || true
fi

echo "🚀 Starting ELK (Elasticsearch + Kibana)..."
cd $HOME/rootkit
docker-compose up -d

echo "✅ Setup complete!"
echo "Open Kibana at: http://localhost:5601 (in the VM browser)."

#!/bin/bash
# ╔══════════════════════════════════════════╗
# ║     CyberKit - Auto Setup & Launcher     ║
# ╚══════════════════════════════════════════╝

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║     CYBERKIT - INSTALLING DEPENDENCIES   ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "  [!] Python3 not found. Please install Python 3.7+"
  exit 1
fi

# Check pip
if ! command -v pip3 &>/dev/null; then
  echo "  [!] pip3 not found. Installing..."
  python3 -m ensurepip --upgrade
fi

# Install Flask
echo "  [*] Installing Flask..."
pip3 install flask --quiet --break-system-packages 2>/dev/null || pip3 install flask --quiet

echo "  [✔] Dependencies ready."
echo ""

# Launch
python3 app.py

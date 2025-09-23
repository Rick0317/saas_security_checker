#!/usr/bin/env bash

# SaaS Security Checker Installation Script with uv
# This script installs all required dependencies and tools using uv

set -e

echo "🔧 SaaS Security Checker Installation Script (with uv)"
echo "======================================================"

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "❌ uv not found. Installing uv..."
    
    # Install uv
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        curl -LsSf https://astral.sh/uv/install.sh | sh
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        curl -LsSf https://astral.sh/uv/install.sh | sh
    else
        echo "❌ Unsupported operating system: $OSTYPE"
        echo "Please install uv manually: https://github.com/astral-sh/uv"
        exit 1
    fi
    
    # Add uv to PATH
    export PATH="$HOME/.cargo/bin:$PATH"
    
    # Verify installation
    if ! command -v uv &> /dev/null; then
        echo "❌ Failed to install uv. Please install manually:"
        echo "   curl -LsSf https://astral.sh/uv/install.sh | sh"
        exit 1
    fi
else
    echo "✅ uv already installed"
fi

echo "📦 Installing Python dependencies with uv..."

# Install dependencies using uv
uv sync

echo "✅ Python dependencies installed successfully!"

# Check if running on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "📱 Detected macOS"
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "❌ Homebrew not found. Please install Homebrew first:"
        echo "   /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        exit 1
    fi
    
    echo "🍺 Installing system dependencies via Homebrew..."
    
    # Install nmap
    if ! command -v nmap &> /dev/null; then
        echo "🔍 Installing nmap..."
        brew install nmap
    else
        echo "✅ nmap already installed"
    fi
    
    # Install SQLMap
    if [ ! -d "sqlmap" ]; then
        echo "🗄️ Installing SQLMap..."
        git clone https://github.com/sqlmapproject/sqlmap.git
    else
        echo "✅ SQLMap already installed"
    fi
    
    # Install Nikto (optional)
    if ! command -v nikto &> /dev/null; then
        echo "🕷️ Installing Nikto..."
        brew install nikto
    else
        echo "✅ Nikto already installed"
    fi
    
    # Install additional tools
    echo "🛠️ Installing additional security tools..."
    brew install curl wget git
    
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "🐧 Detected Linux"
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        echo "⚠️ Running as root. This is not recommended for security reasons."
    fi
    
    # Detect package manager
    if command -v apt-get &> /dev/null; then
        echo "📦 Using apt-get package manager..."
        
        # Update package list
        sudo apt-get update
        
        # Install nmap
        sudo apt-get install -y nmap
        
        # Install additional tools
        sudo apt-get install -y curl wget git
        
        # Install Nikto
        sudo apt-get install -y nikto
        
    elif command -v yum &> /dev/null; then
        echo "📦 Using yum package manager..."
        
        # Install nmap
        sudo yum install -y nmap
        
        # Install additional tools
        sudo yum install -y curl wget git
        
    elif command -v dnf &> /dev/null; then
        echo "📦 Using dnf package manager..."
        
        # Install nmap
        sudo dnf install -y nmap
        
        # Install additional tools
        sudo dnf install -y curl wget git
        
    else
        echo "❌ Unsupported package manager. Please install dependencies manually."
        exit 1
    fi
    
    # Install SQLMap
    if [ ! -d "sqlmap" ]; then
        echo "🗄️ Installing SQLMap..."
        git clone https://github.com/sqlmapproject/sqlmap.git
    else
        echo "✅ SQLMap already installed"
    fi
    
else
    echo "❌ Unsupported operating system: $OSTYPE"
    echo "Please install dependencies manually:"
    echo "- nmap"
    echo "- SQLMap"
    echo "- Nikto (optional)"
    exit 1
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p reports
mkdir -p logs

# Set permissions
echo "🔐 Setting permissions..."
chmod +x main.py
chmod +x install.sh
chmod +x example.py

echo ""
echo "✅ Installation completed successfully!"
echo ""
echo "🚀 To run the security checker:"
echo "   uv run python main.py --target https://example.com"
echo ""
echo "📖 For more options:"
echo "   uv run python main.py --help"
echo ""
echo "📋 Available tests:"
echo "   uv run python main.py --list-tests"
echo ""
echo "🧪 Run examples:"
echo "   uv run python example.py"
echo ""
echo "⚠️  Important Notes:"
echo "   - Only test systems you own or have permission to test"
echo "   - Some tests may be intrusive and should be run carefully"
echo "   - Review the configuration file (config.yaml) before running"
echo "   - Reports will be saved in the ./reports directory"
echo ""
echo "🔧 Troubleshooting:"
echo "   - If SQLMap is not found, ensure it's in your PATH or in the sqlmap/ directory"
echo "   - If nmap requires sudo, you may need to run with elevated privileges"
echo "   - Check the logs directory for detailed error information"
echo ""
echo "📚 uv Commands:"
echo "   - uv sync                    # Install dependencies"
echo "   - uv add <package>           # Add new dependency"
echo "   - uv remove <package>        # Remove dependency"
echo "   - uv run <command>           # Run command in virtual environment"
echo "   - uv lock                    # Update lock file"
echo ""
echo "Happy security testing! 🔒"
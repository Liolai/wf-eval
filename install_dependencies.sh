#!/bin/bash
set -euo pipefail

# =======================================================================
# Minimal dependencies installation script for wf-eval project
# =======================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_ubuntu_version() {
    if [[ ! -f /etc/os-release ]]; then
        print_error "Cannot detect OS version"
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        print_warning "This script is designed for Ubuntu. Detected: $ID"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    if [[ "$VERSION_ID" != "22.04" ]]; then
        print_warning "This script is designed for Ubuntu 22.04. Detected: $VERSION_ID"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    print_success "OS check passed: $PRETTY_NAME"
}

update_system() {
    print_status "Updating system packages..."
    sudo apt update
    sudo apt upgrade -y
    print_success "System updated"
}

install_basic_tools() {
    print_status "Installing essential tools..."
    sudo apt install -y \
        curl \
        wget \
        unzip \
        build-essential
    print_success "Essential tools installed"
}

install_python_dependencies() {
    print_status "Installing Python and required packages..."
    sudo apt install -y \
        python3 \
        python3-pip \
        python3-venv
    
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    pip install --upgrade pip
    pip install selenium scapy pandas numpy matplotlib tqdm
    deactivate
    print_success "Python environment ready"
}

install_chrome_and_chromedriver() {
    print_status "Installing specific Chrome and ChromeDriver versions..."
    
    # Specific versions
    CHROME_VERSION="138.0.7204.100"
    CHROMEDRIVER_VERSION="138.0.7204.183"
    
    # Install specific Chrome version
    print_status "Installing Google Chrome ${CHROME_VERSION}"
    wget -q -O /tmp/chrome.deb "https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/google-chrome-stable_${CHROME_VERSION}-1_amd64.deb"
    sudo dpkg -i /tmp/chrome.deb || sudo apt-get install -f -y
    rm -f /tmp/chrome.deb
    
    # Install specific ChromeDriver version
    print_status "Installing ChromeDriver ${CHROMEDRIVER_VERSION}"
    wget -q -O /tmp/chromedriver.zip "https://storage.googleapis.com/chrome-for-testing-public/${CHROMEDRIVER_VERSION}/linux64/chromedriver-linux64.zip"
    sudo unzip -o /tmp/chromedriver.zip -d /tmp/
    sudo mv /tmp/chromedriver-linux64/chromedriver /usr/local/bin/
    sudo chmod +x /usr/local/bin/chromedriver
    sudo rm -rf /tmp/chromedriver.zip /tmp/chromedriver-linux64
    
    print_success "Chrome ${CHROME_VERSION} and ChromeDriver ${CHROMEDRIVER_VERSION} installed"
}

install_networking_tools() {
    print_status "Installing networking tools..."
    sudo apt install -y \
        tcpdump \
        iproute2 \
        iptables
    print_success "Networking tools installed"
}

install_ebpf_minimal() {
    print_status "Installing minimal eBPF dependencies..."
    sudo apt install -y \
        clang \
        llvm \
        libbpf-dev \
        linux-headers-$(uname -r) \
        linux-headers-generic \
        linux-libc-dev \
        libc6-dev \
        gcc-multilib
    print_success "eBPF dependencies installed"
}

create_output_directories() {
    print_status "Creating output directories..."
    
    mkdir -p out/pcaps out/plots
    print_success "Output directories created"
}

verify_installation() {
    print_status "Verifying installation..."
    
    # Verify Python
    if python3 --version >/dev/null 2>&1; then
        print_success "Python3: $(python3 --version)"
    else
        print_error "Python3 not found"
    fi
    
    # Verify Chrome
    if google-chrome --version >/dev/null 2>&1; then
        print_success "Chrome: $(google-chrome --version)"
    else
        print_error "Google Chrome not found"
    fi
    
    # Verify ChromeDriver
    if chromedriver --version >/dev/null 2>&1; then
        print_success "ChromeDriver: $(chromedriver --version)"
    else
        print_error "ChromeDriver not found"
    fi
    
    # Verify Clang
    if clang --version >/dev/null 2>&1; then
        print_success "Clang: $(clang --version | head -1)"
    else
        print_error "Clang not found"
    fi
    
    # Verify tcpdump
    if tcpdump --version >/dev/null 2>&1; then
        print_success "tcpdump available"
    else
        print_error "tcpdump not found"
    fi
    
    # Verify eBPF loader
    if [[ -f "ebpf/loader" ]]; then
        print_success "eBPF loader built"
    else
        print_warning "eBPF loader not found (normal if build failed)"
    fi
}

show_usage_instructions() {
    echo
    print_success "Installation completed!"
    echo
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Restart your terminal or run: source ~/.bashrc"
    echo "2. Activate the Python virtual environment: source venv/bin/activate"
    echo "3. Setup network namespace: sudo ./setup_netns.sh"
    echo "4. Run measurements: python3 run_measurements.py --mode off"
    echo
    echo -e "${BLUE}Project files overview:${NC}"
    echo "- run_measurements.py: Main measurement script"
    echo "- analyse_pcaps.py: Analyze captured packets"
    echo "- plot_results.py: Generate plots from results"
    echo "- test_cache_disabled.py: Test cache disabled functionality"
    echo "- setup_netns.sh: Setup network namespace"
    echo "- ebpf/: eBPF packet dropper implementation"
    echo
    echo -e "${YELLOW}Note:${NC} You may need to log out and log back in for group membership changes to take effect."
}

main() {
    echo -e "${GREEN}======================================${NC}"
    echo -e "${GREEN} wf-eval Dependencies Installer${NC}"
    echo -e "${GREEN} Ubuntu 22.04 LTS${NC}"
    echo -e "${GREEN}======================================${NC}"
    echo
    
    check_ubuntu_version
    
    if [[ $EUID -eq 0 ]]; then
        print_error "Do not run this script as root. It will use sudo when needed."
        exit 1
    fi
    
    update_system
    install_basic_tools
    install_python_dependencies
    install_chrome_and_chromedriver
    install_networking_tools
    install_ebpf_minimal
    create_output_directories
    verify_installation
    show_usage_instructions
}

# Run only if script is called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi

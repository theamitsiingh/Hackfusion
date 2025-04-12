#!/bin/bash

# Detect operating system
os_name=$(uname -s | tr '[:upper:]' '[:lower:]')
if [[ $os_name == *"mingw"* ]]; then
  os_name="windows"
fi
hw_name=$(uname -m)
case "$hw_name" in
"amd64")
  hw_name="amd64"
  ;;
"x86_64")
  hw_name="amd64"
  ;;
"arm64")
  hw_name="arm64"
  ;;
"aarch64")
  hw_name="arm64"
  ;;
"i686")
  hw_name="386"
  ;;
"armv7l")
  hw_name="arm"
  ;;
*)
  echo "Unsupported hardware: $hw_name"
  exit 1
  ;;
esac

# Detect language
lc_type=$(echo $LC_CTYPE | cut -c 1-2)
if [ -z "$lc_type" ] || [ "$lc_type" = "UT" ]; then
  lc_type=$(echo $LANG | cut -c 1-2)
fi

# Default URL (GitHub release URL)
URLS=("https://github.com/kingparks/windsurf-vip/releases/download/latest")
url=${URLS[0]}

# Validate input
if [ $# -eq 0 ]; then
    echo "Error: No arguments provided"
    echo "Usage: $0 <input>"
    exit 1
fi

# Store input securely
echo "$1" > ~/.windsurf-viprc

# Function for installation
install_windsurf() {
    local os="$1"
    local lang="$2"

    # Validate OS
    if [[ "$os" != "darwin" && "$os" != "linux" && "$os" != "windows" ]]; then
        echo "Unsupported operating system: $os"
        exit 1
    fi

    # Installation for macOS and Linux
    if [[ "$os" == "darwin" || "$os" == "linux" ]]; then
        # Localized messages
        if [ "$lang" = "zh" ]; then
            echo "请输入开机密码"
            echo "警告：请仅在信任来源时继续"
        else
            echo "Please enter the boot password"
            echo "Warning: Proceed only if you trust the source"
        fi

        # Safer download and installation
        sudo mkdir -p /usr/local/bin

        # Download executable
        sudo curl -L -o /usr/local/bin/windsurf-vip "${url}/windsurf-vip_${os}_${hw_name}" || {
            echo "Download failed for ${url}/windsurf-vip_${os}_${hw_name}"
            exit 1
        }
        sudo chmod 755 /usr/local/bin/windsurf-vip

        # Localized completion message
        if [ "$lang" = "zh" ]; then
            echo "安装完成！自动运行；下次可直接输入 windsurf-vip 并回车来运行程序"
        else
            echo "Installation completed! Automatically run; you can run the program by entering windsurf-vip and pressing Enter next time"
        fi

        windsurf-vip
    fi

    # Installation for Windows
    if [[ "$os" == "windows" ]]; then
        # Validate USERPROFILE
        if [ -z "$USERPROFILE" ]; then
            echo "USERPROFILE environment variable not set"
            exit 1
        fi

        # Download executable
        curl -L -o "${USERPROFILE}/Desktop/windsurf-vip.exe" "${url}/windsurf-vip_${os}_${hw_name}.exe" || {
            echo "Download failed for ${url}/windsurf-vip_${os}_${hw_name}.exe"
            exit 1
        }

        # Localized Windows messages
        if [ "$lang" = "zh" ]; then
            echo "安装完成！自动运行; 下次可直接输入 ./windsurf-vip.exe 并回车来运行程序"
            echo "运行后如果360等杀毒软件误报木马，添加信任后，重新输入./windsurf-vip.exe 并回车来运行程序"
        else
            echo "Installation completed! Automatically run; you can run the program by entering ./windsurf-vip.exe and pressing Enter next time"
            echo "After running, if antivirus software reports a false positive, add trust, then re-enter ./windsurf-vip.exe"
        fi

        chmod +x "${USERPROFILE}/Desktop/windsurf-vip.exe"
        "${USERPROFILE}/Desktop/windsurf-vip.exe"
    fi
}

# Main execution
install_windsurf "$os_name" "$lc_type"

exit 0

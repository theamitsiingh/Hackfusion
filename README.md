# HackFusion - Advanced AI-Powered Cybersecurity Toolkit

<p align="center">
  <img src="HackFusion/assets/logo.svg" alt="HackFusion Logo" width="200"/>
</p>

HackFusion is a comprehensive, AI-powered cybersecurity toolkit that integrates advanced automation, machine learning, and state-of-the-art security tools to streamline penetration testing, vulnerability assessment, and security analysis tasks.

## Installation in Kali Linux

1. Clone the repository:
```bash
git clone https://github.com/theamitsiingh/hackfusion.git
cd HackFusion
```

2. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

4. Set up OpenAI API key:
```bash
export OPENAI_API_KEY='your-api-key-here'
```

5. Run HackFusion:
```bash
python3 src/main.py
```

## Required Tools

HackFusion requires the following tools to be installed in Kali Linux:
- Python 3.8 or higher
- nmap
- whois
- OpenAI API key

Most of these tools come pre-installed in Kali Linux. If any are missing, you can install them using:
```bash
sudo apt update
sudo apt install -y python3-pip python3-venv nmap whois
```

## Directory Structure
```
HackFusion/
├── assets/
│   ├── ascii_art/
│   ├── logo.svg
│   └── sounds/
├── config/
│   └── tools.yaml
├── docs/
├── src/
│   ├── main.py
│   ├── menu.py
│   ├── ai_assistant.py
│   ├── error_management/
│   │   ├── __init__.py
│   │   └── error_logger.py
│   ├── tools_integration/
│   │   ├── information_gathering.py
│   │   ├── vulnerability_analysis.py
│   │   ├── network_attacks.py
│   │   ├── web_application.py
│   │   ├── wireless_attacks.py
│   │   ├── password_attacks.py
│   │   ├── reverse_engineering.py
│   │   ├── forensics.py
│   │   └── exploitation.py
│   └── utils/
│       ├── kali_tools.py
│       ├── logging_config.py
│       ├── tool_decorators.py
│       └── config_loader.py
├── templates/
├── tests/
├── reports/
├── requirements.txt
└── README.md
```

## Key Features
- 🧠 Advanced AI Integration
  - Natural language processing for command interpretation
  - Intelligent tool selection and automation
  - Adaptive learning from previous scans

- 🛡️ Comprehensive Security Testing
  - 🔍 Advanced information gathering
  - 🎯 Intelligent vulnerability analysis
  - 🌐 Dynamic web application testing
- 🔧 Specialized Tools Integration
  - 📡 Advanced wireless network testing
  - 🔑 Enhanced password attacks and cracking
  - 🔬 Sophisticated reverse engineering
  - ⚔️ Targeted exploitation frameworks
  - 🔎 Advanced digital forensics
  - 🌐 Network attack simulations

- 📊 Professional Reporting
  - Automated report generation
  - Detailed vulnerability documentation
  - Custom templates and formats
  - Executive summaries and technical details

- 🛠️ Enhanced Features
  - Error management and logging
  - Tool execution decorators
  - Configurable logging system
  - Modular architecture
  - Extensive test coverage

## Usage
1. Start HackFusion:
```bash
python3 src/main.py
```

2. Choose from the menu options or use the AI assistant by typing your request in natural language.

3. Follow the prompts to execute security tests and generate reports.

## Reports
Reports and logs are automatically saved in the `reports` directory:
- `report_TIMESTAMP.md`: Detailed findings and recommendations
- `logs_TIMESTAMP.json`: Execution logs with timestamps and results

## Contributing
Feel free to submit issues, fork the repository, and create pull requests for any improvements.

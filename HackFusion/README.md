# HackFusion - Advanced Cybersecurity Toolkit

HackFusion is an AI-powered cybersecurity toolkit that helps automate and streamline various security testing tasks.

## Installation in Kali Linux

1. Clone the repository:
```bash
git clone https://github.com/yourusername/HackFusion.git
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
├── config/
│   └── tools.yaml
├── src/
│   ├── main.py
│   ├── menu.py
│   ├── ai_assistant.py
│   └── tools_integration/
│       ├── information_gathering.py
│       ├── vulnerability_analysis.py
│       └── ...
├── reports/
├── requirements.txt
└── README.md
```

## Features
- 🤖 AI-powered task automation
- 🔍 Information gathering
- 🎯 Vulnerability analysis
- 🌐 Web application testing
- 📡 Wireless network testing
- 🔑 Password attacks
- 🔧 Reverse engineering tools
- ⚔️ Exploitation tools
- 🔎 Digital forensics
- 📊 Automated report generation

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

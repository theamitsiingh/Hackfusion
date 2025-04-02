"""
Menu system for HackFusion
"""

import sys
import os
import json
import traceback
from typing import Dict, Any, Optional, List
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.prompt import Prompt
from rich.markdown import Markdown
from rich import box

from src.utils.config_loader import ConfigLoader
from src.utils.kali_tools import KaliToolsManager
from src.tools_integration.information_gathering import InformationGathering
from src.tools_integration.vulnerability_analysis import VulnerabilityAnalysis
from src.tools_integration.web_application import WebApplicationAnalysis
from src.tools_integration.password_attacks import PasswordAttacks
from src.tools_integration.wireless_attacks import WirelessAttacks
from src.tools_integration.reverse_engineering import ReverseEngineering
from src.tools_integration.exploitation import ExploitationTools
from src.tools_integration.forensics import Forensics
from src.tools_integration.reporting import ReportGenerator
from src.ai_assistant import AIAssistant

class Menu:
    """Main menu class"""
    
    def __init__(self):
        """Initialize menu"""
        self.console = Console()
        
        # Initialize Kali Tools Manager
        try:
            print("Initializing Kali Tools Manager...")
            self.kali_tools = KaliToolsManager()
            print("Checking installed tools...")
            self.tool_status = self.kali_tools.check_all_tools()
            missing_tools = [tool for tool, installed in self.tool_status.items() if not installed]
            if missing_tools:
                print("[yellow]Some Kali tools are missing:[/yellow]")
                for tool in missing_tools:
                    print(f"[yellow]- {tool}[/yellow]")
                if Prompt.ask("[cyan]Would you like to install missing tools?[/cyan] (y/n)", default="y").lower() == "y":
                    self.kali_tools.install_missing_tools()
        except Exception as e:
            print(f"Error initializing Kali Tools Manager: {str(e)}")
            print("Full traceback:")
            traceback.print_exc()
        
        try:
            print("Initializing AI Assistant...")
            print(f"OPENAI_API_KEY present: {bool(os.getenv('OPENAI_API_KEY'))}")
            print(f"OPENAI_API_KEY value: {os.getenv('OPENAI_API_KEY')[:10]}...")
            self.ai_assistant = AIAssistant()
            self.has_ai = True
            print("AI Assistant initialized successfully")
        except Exception as e:
            print(f"AI Assistant initialization error: {str(e)}")
            print("Full traceback:")
            traceback.print_exc()
            self.console.print(f"[red]AI Assistant not available: {e}[/red]")
            self.console.print("[yellow]To enable AI features, set the OPENAI_API_KEY environment variable[/yellow]")
            self.has_ai = False
        
        self.init_modules()
        
    def init_modules(self):
        """Initialize tool modules"""
        try:
            self.info_gathering = InformationGathering()
            self.vuln_analysis = VulnerabilityAnalysis()
            self.web_analysis = WebApplicationAnalysis()
            self.wireless = WirelessAttacks()
            self.password = PasswordAttacks()
            self.reverse = ReverseEngineering()
            self.exploitation = ExploitationTools()
            self.forensics = Forensics()
            self.reporting = ReportGenerator()
        except Exception as e:
            self.console.print(f"[red]Warning: Some modules failed to initialize: {e}[/red]")
            
    def print_menu(self):
        """Print main menu"""
        # Create title
        title = Text()
        title.append("HackFusion", style="bold cyan")
        title.append(" - ", style="white")
        title.append("Advanced Cybersecurity Toolkit", style="bold green")
        
        # Create menu table
        table = Table(box=box.ROUNDED, show_header=False, show_edge=False)
        table.add_column("Option", style="cyan")
        table.add_column("Description", style="white")
        
        if self.has_ai:
            table.add_row(
                "AI",
                Text("Tell me what you want to do", style="green")
            )
            table.add_row(
                "",
                Text("💡 Try: 'I want to hack a network' or 'Find vulnerabilities'", style="dim")
            )
            table.add_row("", "")  # Spacer
            
        table.add_row("1", "🔍 Information Gathering")
        table.add_row("2", "🎯 Vulnerability Analysis")
        table.add_row("3", "🌐 Web Application Analysis")
        table.add_row("4", "🔑 Password Attacks")
        table.add_row("5", "📡 Wireless Attacks")
        table.add_row("6", "🔧 Reverse Engineering")
        table.add_row("7", "⚔️ Exploitation Tools")
        table.add_row("8", "🔎 Forensics")
        table.add_row("9", "📊 Report Generation")
        table.add_row("T", "🛠️ Manage Kali Tools")
        table.add_row("0", "❌ Exit")
        
        # Create panel
        panel = Panel(
            table,
            title=title,
            border_style="blue",
            padding=(1, 2)
        )
        
        self.console.clear()
        self.console.print(panel)
        
    def get_example_targets(self, tool: str) -> List[str]:
        """Get example targets for a tool"""
        examples = {
            "nmap": ["192.168.1.0/24", "10.0.0.0/16", "172.16.0.0/12"],
            "whois": ["example.com", "google.com", "microsoft.com"],
            "vuln_scan": ["192.168.1.100", "https://example.com", "10.0.0.1"],
            "web_scan": ["http://example.com", "https://test.local", "http://192.168.1.100"]
        }
        return examples.get(tool, [])
        
    def execute_ai_plan(self, plan: Dict[str, Any]) -> None:
        """Execute AI-generated action plan"""
        results = []
        logs = []
        
        # Show plan overview
        title = Text()
        title.append("🎯 ", style="green")
        title.append(plan['description'], style="bold white")
        
        tools_text = Text()
        tools_text.append("Required tools: ", style="blue")
        tools_text.append(", ".join(plan['tools']), style="yellow")
        
        panel = Panel(
            tools_text,
            title=title,
            border_style="blue"
        )
        self.console.print(panel)
        
        # Execute steps
        for i, step in enumerate(plan['steps'], 1):
            step_title = Text()
            step_title.append(f"Step {i}: ", style="cyan")
            step_title.append(step['action'], style="bold white")
            
            step_panel = Panel(
                step['description'],
                title=step_title,
                border_style="blue"
            )
            self.console.print(step_panel)
            
            try:
                # Get optimal parameters for this step based on previous results
                params = self.ai_assistant.get_next_step_params(step, results)
                
                # Execute the step based on the tool
                result = None
                
                # Log the step execution
                log_entry = {
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'step': i,
                    'action': step['action'],
                    'tool': step['tool'],
                    'params': params,
                    'status': 'started'
                }
                
                if step['tool'] == 'nmap':
                    examples = self.get_example_targets('nmap')
                    self.console.print("[yellow]Example targets:[/yellow] " + ", ".join(examples))
                    target = Prompt.ask("[cyan]Enter target[/cyan]")
                    log_entry['target'] = target
                    result = self.info_gathering.run_nmap_scan(target, params)
                        
                elif step['tool'] == 'whois':
                    examples = self.get_example_targets('whois')
                    self.console.print("[yellow]Example domains:[/yellow] " + ", ".join(examples))
                    domain = Prompt.ask("[cyan]Enter domain[/cyan]")
                    log_entry['target'] = domain
                    result = self.info_gathering.run_whois_lookup(domain)
                    
                elif step['tool'] == 'vuln_scan':
                    examples = self.get_example_targets('vuln_scan')
                    self.console.print("[yellow]Example targets:[/yellow] " + ", ".join(examples))
                    target = Prompt.ask("[cyan]Enter target[/cyan]")
                    log_entry['target'] = target
                    result = self.vuln_analysis.run_scan(target, params)
                    
                elif step['tool'] == 'web_scan':
                    examples = self.get_example_targets('web_scan')
                    self.console.print("[yellow]Example URLs:[/yellow] " + ", ".join(examples))
                    target = Prompt.ask("[cyan]Enter target URL[/cyan]")
                    log_entry['target'] = target
                    result = self.web_analysis.run_scan(target, params)
                    
                else:
                    result = {'error': f'Tool not implemented: {step["tool"]}'}
                
                if result.get('error'):
                    self.console.print(f"[red]Error:[/red] {result['error']}")
                    log_entry['status'] = 'error'
                    log_entry['error'] = result['error']
                else:
                    self.console.print("[green]Success![/green]")
                    log_entry['status'] = 'success'
                    results.append({
                        'step': step,
                        'result': result
                    })
                    
            except Exception as e:
                self.console.print(f"[red]Error executing step:[/red] {e}")
                print("Full traceback:")
                traceback.print_exc()
                log_entry['status'] = 'error'
                log_entry['error'] = str(e)
                
            # Add log entry
            log_entry['end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            logs.append(log_entry)
                
        # Generate report
        try:
            self.console.print("[cyan]Generating report...[/cyan]")
            
            # Create reports directory
            reports_dir = os.path.join(os.getcwd(), 'reports')
            os.makedirs(reports_dir, exist_ok=True)
            
            # Generate timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save logs
            logs_file = os.path.join(reports_dir, f"logs_{timestamp}.json")
            with open(logs_file, 'w') as f:
                json.dump(logs, f, indent=2)
            
            # Generate report with logs
            report_data = {
                'results': results,
                'logs': logs,
                'category': plan['category'],
                'description': plan['description'],
                'tools': plan['tools']
            }
            report = self.ai_assistant.generate_report(report_data)
            
            # Save report
            report_file = os.path.join(reports_dir, f"report_{timestamp}.md")
            with open(report_file, 'w') as f:
                f.write(report)
                
            self.console.print(f"[green]Report saved to:[/green] {report_file}")
            self.console.print(f"[green]Logs saved to:[/green] {logs_file}")
            
        except Exception as e:
            self.console.print(f"[red]Error generating report:[/red] {e}")
            print("Full traceback:")
            traceback.print_exc()
        
    def ai_menu(self):
        """AI-assisted menu"""
        # Show AI prompt
        prompt_panel = Panel(
            Text.from_markup(
                "💡 Examples:\n"
                "• [cyan]I want to hack into a network[/cyan]\n"
                "• [cyan]Find vulnerabilities in my system[/cyan]\n"
                "• [cyan]Test the security of my website[/cyan]\n"
                "• [cyan]Analyze network traffic for suspicious activity[/cyan]"
            ),
            title="What would you like me to help you with?",
            border_style="blue"
        )
        self.console.print(prompt_panel)
        
        user_input = Prompt.ask("[cyan]Your request[/cyan]")
        
        try:
            # Analyze request and get action plan
            self.console.print("[cyan]Analyzing your request...[/cyan]")
            response = self.ai_assistant.analyze_request(user_input)
            
            try:
                plan = json.loads(response)
            except json.JSONDecodeError as e:
                print(f"Error decoding AI response: {str(e)}")
                print("AI Response:")
                print(response)
                raise Exception("Failed to parse AI response")
            
            # Show plan overview
            self.console.print(f"[green]I'll help you {plan['description'].lower()}[/green]")
            
            steps_panel = Panel(
                "\n".join([
                    f"[cyan]{i}.[/cyan] {step['description']}" +
                    (f"\n   [yellow]Note: {step['tool']} functionality is not yet implemented[/yellow]"
                     if step.get('tool') and step['tool'] not in ['nmap', 'whois'] else "")
                    for i, step in enumerate(plan['steps'], 1)
                ]),
                title="Here's what I'm going to do",
                border_style="blue"
            )
            self.console.print(steps_panel)
            
            if Prompt.ask("[cyan]Would you like me to proceed?[/cyan] (y/n)", default="y").lower() == "y":
                self.execute_ai_plan(plan)
            
        except Exception as e:
            print(f"Error in AI menu: {str(e)}")
            print("Full traceback:")
            traceback.print_exc()
        
    def info_gathering_menu(self):
        """Information gathering menu"""
        while True:
            self.console.print("\n[cyan]Information Gathering[/cyan]")
            self.console.print("-" * 30)
            self.console.print("[cyan]1.[/cyan] Nmap Scan")
            self.console.print("[cyan]2.[/cyan] WHOIS Lookup")
            self.console.print("[cyan]0.[/cyan] Back")
            
            choice = Prompt.ask("\n[cyan]Enter choice[/cyan]")
            
            if choice == "1":
                target = Prompt.ask("\n[cyan]Enter target IP/hostname[/cyan]")
                try:
                    result = self.info_gathering.run_nmap_scan(target)
                    self.console.print("\n[cyan]Scan Results:[/cyan]")
                    self.console.print(result['result'])
                except Exception as e:
                    self.console.print(f"\n[red]Error:[/red] {e}")
                    print("Full traceback:")
                    traceback.print_exc()
                    
            elif choice == "2":
                domain = Prompt.ask("\n[cyan]Enter domain name[/cyan]")
                try:
                    result = self.info_gathering.run_whois_lookup(domain)
                    self.console.print("\n[cyan]WHOIS Results:[/cyan]")
                    self.console.print(result['result'])
                except Exception as e:
                    self.console.print(f"\n[red]Error:[/red] {e}")
                    print("Full traceback:")
                    traceback.print_exc()
                    
            elif choice == "0":
                break
                
    def vuln_analysis_menu(self):
        """Vulnerability analysis menu"""
        while True:
            self.console.print("\n[cyan]Vulnerability Analysis[/cyan]")
            self.console.print("-" * 30)
            self.console.print("[cyan]1.[/cyan] Run Vulnerability Scan")
            self.console.print("[cyan]0.[/cyan] Back")
            
            choice = Prompt.ask("\n[cyan]Enter choice[/cyan]")
            
            if choice == "1":
                target = Prompt.ask("\n[cyan]Enter target URL[/cyan]")
                try:
                    result = self.vuln_analysis.run_scan(target)
                    self.console.print("\n[cyan]Scan Results:[/cyan]")
                    self.console.print(result['result'])
                except Exception as e:
                    self.console.print(f"\n[red]Error:[/red] {e}")
                    print("Full traceback:")
                    traceback.print_exc()
                    
            elif choice == "0":
                break
                
    def web_analysis_menu(self):
        """Web application analysis menu"""
        while True:
            self.console.print("\n[cyan]Web Application Analysis[/cyan]")
            self.console.print("-" * 30)
            self.console.print("[cyan]1.[/cyan] Run Web Application Scan")
            self.console.print("[cyan]0.[/cyan] Back")
            
            choice = Prompt.ask("\n[cyan]Enter choice[/cyan]")
            
            if choice == "1":
                target = Prompt.ask("\n[cyan]Enter target URL[/cyan]")
                try:
                    result = self.web_analysis.run_scan(target)
                    self.console.print("\n[cyan]Scan Results:[/cyan]")
                    self.console.print(result['result'])
                except Exception as e:
                    self.console.print(f"\n[red]Error:[/red] {e}")
                    print("Full traceback:")
                    traceback.print_exc()
                    
            elif choice == "0":
                break
                
    def password_menu(self):
        """Password attacks menu"""
        while True:
            self.console.print("\n[cyan]Password Attacks[/cyan]")
            self.console.print("-" * 30)
            self.console.print("[cyan]1.[/cyan] Run Password Attack")
            self.console.print("[cyan]0.[/cyan] Back")
            
            choice = Prompt.ask("\n[cyan]Enter choice[/cyan]")
            
            if choice == "1":
                target = Prompt.ask("\n[cyan]Enter target[/cyan]")
                try:
                    result = self.password.run_attack(target)
                    self.console.print("\n[cyan]Attack Results:[/cyan]")
                    self.console.print(result['result'])
                except Exception as e:
                    self.console.print(f"\n[red]Error:[/red] {e}")
                    print("Full traceback:")
                    traceback.print_exc()
                    
            elif choice == "0":
                break
                
    def wireless_menu(self):
        """Wireless attacks menu"""
        while True:
            self.console.print("\n[cyan]Wireless Attacks[/cyan]")
            self.console.print("-" * 30)
            self.console.print("[cyan]1.[/cyan] Run Wireless Attack")
            self.console.print("[cyan]0.[/cyan] Back")
            
            choice = Prompt.ask("\n[cyan]Enter choice[/cyan]")
            
            if choice == "1":
                target = Prompt.ask("\n[cyan]Enter target[/cyan]")
                try:
                    result = self.wireless.run_attack(target)
                    self.console.print("\n[cyan]Attack Results:[/cyan]")
                    self.console.print(result['result'])
                except Exception as e:
                    self.console.print(f"\n[red]Error:[/red] {e}")
                    print("Full traceback:")
                    traceback.print_exc()
                    
            elif choice == "0":
                break
                
    def reverse_menu(self):
        """Reverse engineering menu"""
        while True:
            self.console.print("\n[cyan]Reverse Engineering[/cyan]")
            self.console.print("-" * 30)
            self.console.print("[cyan]1.[/cyan] Run Reverse Engineering")
            self.console.print("[cyan]0.[/cyan] Back")
            
            choice = Prompt.ask("\n[cyan]Enter choice[/cyan]")
            
            if choice == "1":
                target = Prompt.ask("\n[cyan]Enter target[/cyan]")
                try:
                    result = self.reverse.run_reverse_engineering(target)
                    self.console.print("\n[cyan]Results:[/cyan]")
                    self.console.print(result['result'])
                except Exception as e:
                    self.console.print(f"\n[red]Error:[/red] {e}")
                    print("Full traceback:")
                    traceback.print_exc()
                    
            elif choice == "0":
                break
                
    def exploitation_menu(self):
        """Exploitation tools menu"""
        while True:
            self.console.print("\n[cyan]Exploitation Tools[/cyan]")
            self.console.print("-" * 30)
            self.console.print("[cyan]1.[/cyan] Run Exploitation Tool")
            self.console.print("[cyan]0.[/cyan] Back")
            
            choice = Prompt.ask("\n[cyan]Enter choice[/cyan]")
            
            if choice == "1":
                target = Prompt.ask("\n[cyan]Enter target[/cyan]")
                try:
                    result = self.exploitation.run_exploitation_tool(target)
                    self.console.print("\n[cyan]Results:[/cyan]")
                    self.console.print(result['result'])
                except Exception as e:
                    self.console.print(f"\n[red]Error:[/red] {e}")
                    print("Full traceback:")
                    traceback.print_exc()
                    
            elif choice == "0":
                break
                
    def forensics_menu(self):
        """Forensics menu"""
        while True:
            self.console.print("\n[cyan]Forensics[/cyan]")
            self.console.print("-" * 30)
            self.console.print("[cyan]1.[/cyan] Run Forensics Tool")
            self.console.print("[cyan]0.[/cyan] Back")
            
            choice = Prompt.ask("\n[cyan]Enter choice[/cyan]")
            
            if choice == "1":
                target = Prompt.ask("\n[cyan]Enter target[/cyan]")
                try:
                    result = self.forensics.run_forensics_tool(target)
                    self.console.print("\n[cyan]Results:[/cyan]")
                    self.console.print(result['result'])
                except Exception as e:
                    self.console.print(f"\n[red]Error:[/red] {e}")
                    print("Full traceback:")
                    traceback.print_exc()
                    
            elif choice == "0":
                break
                
    def reporting_menu(self):
        """Reporting menu"""
        while True:
            self.console.print("\n[cyan]Reporting[/cyan]")
            self.console.print("-" * 30)
            self.console.print("[cyan]1.[/cyan] Generate Report")
            self.console.print("[cyan]0.[/cyan] Back")
            
            choice = Prompt.ask("\n[cyan]Enter choice[/cyan]")
            
            if choice == "1":
                try:
                    result = self.reporting.generate_report()
                    self.console.print("\n[cyan]Report Results:[/cyan]")
                    self.console.print(result['result'])
                except Exception as e:
                    self.console.print(f"\n[red]Error:[/red] {e}")
                    print("Full traceback:")
                    traceback.print_exc()
                    
            elif choice == "0":
                break
                
    def manage_tools_menu(self):
        """Kali tools management menu"""
        while True:
            self.console.print("\n[cyan]Kali Tools Management[/cyan]")
            self.console.print("-" * 30)
            self.console.print("[cyan]1.[/cyan] Check Tool Status")
            self.console.print("[cyan]2.[/cyan] Install Missing Tools")
            self.console.print("[cyan]0.[/cyan] Back")
            
            choice = Prompt.ask("\n[cyan]Enter choice[/cyan]")
            
            if choice == "1":
                try:
                    status = self.kali_tools.check_all_tools()
                    table = Table(show_header=True, header_style="bold cyan")
                    table.add_column("Tool")
                    table.add_column("Status")
                    table.add_column("Description")
                    
                    for tool, installed in status.items():
                        info = self.kali_tools.get_tool_info(tool)
                        table.add_row(
                            tool,
                            "[green]Installed[/green]" if installed else "[red]Not Installed[/red]",
                            info['description']
                        )
                        
                    self.console.print(table)
                    
                except Exception as e:
                    self.console.print(f"[red]Error checking tools: {str(e)}[/red]")
                    print("Full traceback:")
                    traceback.print_exc()
                    
            elif choice == "2":
                try:
                    if not self.kali_tools.is_kali:
                        self.console.print("[red]Error: Tool installation is only supported on Kali Linux[/red]")
                        continue
                        
                    self.console.print("[cyan]Installing missing tools...[/cyan]")
                    if self.kali_tools.install_missing_tools():
                        self.console.print("[green]All missing tools have been installed[/green]")
                    else:
                        self.console.print("[red]Some tools failed to install. Check the output above for details.[/red]")
                        
                except Exception as e:
                    self.console.print(f"[red]Error installing tools: {str(e)}[/red]")
                    print("Full traceback:")
                    traceback.print_exc()
                    
            elif choice == "0":
                break
                
    def run(self):
        """Run the menu"""
        while True:
            try:
                self.print_menu()
                choice = Prompt.ask("\nEnter choice", default="0")
                
                if choice == "AI" and self.has_ai:
                    self.ai_menu()
                elif choice == "1":
                    self.info_gathering_menu()
                elif choice == "2":
                    self.vuln_analysis_menu()
                elif choice == "3":
                    self.web_analysis_menu()
                elif choice == "4":
                    self.password_menu()
                elif choice == "5":
                    self.wireless_menu()
                elif choice == "6":
                    self.reverse_menu()
                elif choice == "7":
                    self.exploitation_menu()
                elif choice == "8":
                    self.forensics_menu()
                elif choice == "9":
                    self.reporting_menu()
                elif choice.upper() == "T":
                    self.manage_tools_menu()
                elif choice == "0":
                    break
                else:
                    self.console.print("[red]Invalid choice[/red]")
                    
            except Exception as e:
                print(f"Error in main menu loop: {str(e)}")
                print("Full traceback:")
                traceback.print_exc()
                continue

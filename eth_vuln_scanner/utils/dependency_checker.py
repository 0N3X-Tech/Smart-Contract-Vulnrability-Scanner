"""
Utility for checking and installing dependencies
"""

import os
import subprocess
import sys
from rich.console import Console
from rich.prompt import Confirm

console = Console()

def check_dependency(command, name=None):
    """
    Check if a command-line dependency is installed
    
    Args:
        command: Command to check
        name: Name of the dependency (defaults to command)
        
    Returns:
        bool: True if installed, False otherwise
    """
    if name is None:
        name = command
        
    try:
        result = subprocess.run(
            [command, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

def check_dependencies():
    """
    Check if all required dependencies are installed
    
    Returns:
        dict: Dictionary of dependencies and their installation status
    """
    dependencies = {
        "slither": check_dependency("slither"),
        "mythril": check_dependency("myth", "mythril"),
        "solc": check_dependency("solc", "solidity compiler")
    }
    
    return dependencies

def install_dependencies(interactive=True):
    """
    Install missing dependencies
    
    Args:
        interactive: Whether to prompt the user before installing
        
    Returns:
        bool: True if all dependencies are installed, False otherwise
    """
    dependencies = check_dependencies()
    missing = [name for name, installed in dependencies.items() if not installed]
    
    if not missing:
        console.print("[green]All dependencies are installed![/green]")
        return True
    
    console.print("[yellow]The following dependencies are missing:[/yellow]")
    for name in missing:
        console.print(f"  - {name}")
    
    if interactive:
        install = Confirm.ask("Would you like to install the missing dependencies?")
        if not install:
            console.print("[yellow]Skipping dependency installation.[/yellow]")
            return False
    
    # Run the installation script
    script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "install_dependencies.sh")
    
    if not os.path.exists(script_path):
        console.print("[red]Error: Installation script not found.[/red]")
        return False
    
    try:
        console.print("[bold]Installing dependencies...[/bold]")
        result = subprocess.run(
            ["bash", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.returncode == 0:
            console.print("[green]Dependencies installed successfully![/green]")
            return True
        else:
            console.print(f"[red]Error installing dependencies:[/red]\n{result.stderr}")
            return False
    except subprocess.SubprocessError as e:
        console.print(f"[red]Error running installation script:[/red] {str(e)}")
        return False

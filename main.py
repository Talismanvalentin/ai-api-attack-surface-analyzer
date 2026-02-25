"""CLI entrypoint for the API attack-surface workflow.

This module wires together three phases:
1. Swagger/OpenAPI discovery from a target base URL.
2. Spec parsing into a normalized endpoint list.
3. Heuristic security analysis of each endpoint.
"""

import argparse

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.analyzer import AttackSurfaceAnalyzer
from core.swagger_discovery import SwaggerDiscovery
from core.swagger_parser import SwaggerParser

console = Console()


def run_discovery(target: str) -> str | None:
    """Discover likely Swagger/OpenAPI URLs and return the first hit.

    Returning the first candidate keeps the scan flow fast for interactive use.
    If multiple docs exist, users can rerun `analyze` manually with a chosen URL.
    """
    console.print("\n[bold yellow][*] Starting Swagger discovery...[/bold yellow]\n")

    discovery = SwaggerDiscovery(target)
    found_urls = discovery.discover()

    if not found_urls:
        console.print("[bold red][!] No Swagger documentation found.[/bold red]")
        return None

    console.print(f"\n[bold green][+] Using Swagger: {found_urls[0]}[/bold green]\n")
    return found_urls[0]


def run_analysis(swagger_url: str) -> None:
    """Fetch a Swagger document, extract endpoints, and print risk findings."""
    console.print(f"\n[bold cyan][*] Fetching Swagger from:[/bold cyan] {swagger_url}\n")

    parser = SwaggerParser(swagger_url)

    if not parser.fetch_swagger():
        console.print("[bold red][!] Failed to fetch Swagger.[/bold red]")
        return

    endpoints = parser.extract_endpoints()

    if not endpoints:
        console.print("[bold red][!] No endpoints found.[/bold red]")
        return

    # Show the raw attack surface before applying heuristics so analysts can
    # verify that the parser interpreted the specification correctly.
    table = Table(title="Extracted Endpoints", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Method", style="bold magenta")
    table.add_column("Path", style="cyan")

    for endpoint in endpoints:
        table.add_row(endpoint["method"], endpoint["path"])

    console.print(table)

    analyzer = AttackSurfaceAnalyzer(endpoints)
    findings = analyzer.analyze()

    if not findings:
        console.print("\n[bold green][+] No obvious attack vectors detected.[/bold green]\n")
        return

    # Findings are intentionally flattened into one row per endpoint to keep
    # triage fast during reconnaissance and bug-hunting workflows.
    findings_table = Table(title="Potential Attack Vectors", box=box.MINIMAL_DOUBLE_HEAD)
    findings_table.add_column("Severity", style="bold")
    findings_table.add_column("Method", style="magenta")
    findings_table.add_column("Path", style="cyan")
    findings_table.add_column("Risk", style="yellow")

    for finding in findings:
        findings_table.add_row(
            finding["severity"],
            finding["method"],
            finding["path"],
            " | ".join(finding["risks"]),
        )

    console.print(findings_table)


def interactive_menu() -> None:
    """Render the TUI menu used when no CLI subcommand is provided."""
    console.print(
        Panel(
            "[bold cyan]AI API Attack Surface Analyzer v0.1[/bold cyan]",
            expand=False,
        )
    )

    console.print("\n[bold]Select an option:[/bold]\n")
    console.print("[1] Discover Swagger")
    console.print("[2] Analyze Swagger JSON")
    console.print("[3] Full Scan (Discover + Analyze)")
    console.print("[4] Exit\n")

    choice = input("➜ Enter choice: ").strip()

    if choice == "1":
        target = input("➜ Enter base URL (e.g. https://api.target.com): ").strip()
        run_discovery(target)

    elif choice == "2":
        swagger_url = input("➜ Enter full Swagger JSON URL: ").strip()
        run_analysis(swagger_url)

    elif choice == "3":
        target = input("➜ Enter base URL: ").strip()
        swagger_url = run_discovery(target)
        if swagger_url:
            run_analysis(swagger_url)

    elif choice == "4":
        console.print("\n[bold green]Exiting.[/bold green]\n")
        return

    else:
        console.print("\n[bold red]Invalid option.[/bold red]\n")


def main() -> None:
    """Parse command-line arguments and dispatch the selected workflow."""
    parser = argparse.ArgumentParser(description="AI API Attack Surface Analyzer")

    subparsers = parser.add_subparsers(dest="command")

    discover_parser = subparsers.add_parser("discover", help="Discover Swagger endpoints")
    discover_parser.add_argument("target", help="Base URL")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze Swagger JSON")
    analyze_parser.add_argument("swagger_url", help="Full Swagger JSON URL")

    scan_parser = subparsers.add_parser("scan", help="Discover and analyze automatically")
    scan_parser.add_argument("target", help="Base URL")

    args = parser.parse_args()

    if not args.command:
        interactive_menu()
        return

    if args.command == "discover":
        run_discovery(args.target)

    elif args.command == "analyze":
        run_analysis(args.swagger_url)

    elif args.command == "scan":
        swagger_url = run_discovery(args.target)
        if swagger_url:
            run_analysis(swagger_url)


if __name__ == "__main__":
    main()

import sys
import argparse
from detector import PromptInjectionDetector, ScanResult
 
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
WHITE  = "\033[97m"
 
LEVEL_COLORS = {
    "SAFE":     GREEN,
    "LOW":      CYAN,
    "MEDIUM":   YELLOW,
    "HIGH":     RED,
    "CRITICAL": RED + BOLD,
}
 
CONFIDENCE_COLORS = {
    "low":    GRAY,
    "medium": YELLOW,
    "high":   RED,
}
 
 
def risk_bar(score: int) -> str:
    """Render a visual risk bar."""
    filled = int(score / 5)
    empty  = 20 - filled
    return f"[{'█' * filled}{'░' * empty}] {score}/100"
 
 
def print_result(result: ScanResult) -> None:
    level_color = LEVEL_COLORS.get(result.risk_level, WHITE)
 
    print(f"\n{BOLD}{'─' * 54}{RESET}")
    print(f"{BOLD}  Aggio Security — Prompt Injection Scan{RESET}")
    print(f"{'─' * 54}")
 
    # Risk level
    print(f"\n  Risk Level : {level_color}{BOLD}{result.risk_level}{RESET}")
    print(f"  Risk Score : {level_color}{risk_bar(result.risk_score)}{RESET}")
 
    # Input preview
    preview = result.input_text[:80] + "..." if len(result.input_text) > 80 else result.input_text
    print(f"\n  Input      : {GRAY}\"{preview}\"{RESET}")
 
    # Summary
    print(f"\n  {BOLD}Summary{RESET}")
    print(f"  {result.summary}")
 
    # Findings
    print(f"\n  {BOLD}Findings{RESET}")
    for f in result.findings:
        icon   = "🔴" if f.detected else "🟢"
        c_col  = CONFIDENCE_COLORS.get(f.confidence, WHITE)
        status = f"{RED}DETECTED{RESET}" if f.detected else f"{GREEN}CLEAR{RESET}"
        conf   = f"{c_col}[{f.confidence.upper()}]{RESET}" if f.detected else ""
 
        print(f"\n  {icon}  {BOLD}{f.category}{RESET}  {status} {conf}")
        print(f"     {GRAY}{f.explanation}{RESET}")
        if f.detected:
            print(f"     {CYAN}→ {f.recommendation}{RESET}")
 
    print(f"\n{'─' * 54}")
    print(f" {GRAY} Aggio Security {RESET} ")
    print(f"{'─' * 54}\n")

 
def main():
    parser = argparse.ArgumentParser(
        description="Aggio Security — Prompt Injection Detector",
        epilog='Example: python cli.py "Ignore all previous instructions."',
    )
    parser.add_argument("text", nargs="?", help="Text to scan")
    parser.add_argument("--file", "-f", help="Path to a text file to scan")
    args = parser.parse_args()
 
    # Resolve input source
    if args.file:
        with open(args.file, "r") as fh:
            text = fh.read()
    elif args.text:
        text = args.text
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        parser.print_help()
        sys.exit(1)
 
    print(f"{GRAY}Scanning with Aggio Security detector...{RESET}")
 
    try:
        detector = PromptInjectionDetector()
        result   = detector.scan(text)
        print_result(result)
 
        # Exit code reflects risk level
        exit_codes = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        sys.exit(exit_codes.get(result.risk_level, 0))
 
    except ValueError as e:
        print(f"{RED}Error: {e}{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}Scan failed: {e}{RESET}")
        sys.exit(1)
 
 
if __name__ == "__main__":
    main()
"""Command-line interface for WPT scanner."""

import argparse
import sys
from wpt.core.scanner import WebScanner
from wpt.utils.constants import DEFAULT_THREADS


def print_banner():
    """Print WPT banner."""
    print(r"""
                     ,----,
            ,-.----.         ,/   .`| 
       .---.\    /  \      ,`   .'  : 
      /. ./||   :    \   ;    ;     / 
  .--'.  ' ;|   |  .\ :.'___,/    ,'  
 /__./ \ : |.   :  |: ||    :     |   
.--'.  '   \' .|   |   \ :;    |.';  ;   
/___/ \ |    ' '|   : .   /`----'  |  |   
;   \  \;      :;   | |`-'     '   :  ;   
 \   ;  `      ||   | ;        |   |  '   
  .   \    .\  ;:   ' |        '   :  |   
   \   \   ' \ |:   : :        ;   |.'    
    :   '  |--" |   | :        '---'      
     \   \ ;    `---'.|                   
      '---"       `---`                   WPT v2.0

   Web Penetration Testing Tool
   --------------------------------
    """)


def main():
    """Main CLI entry point."""
    print_banner()

    parser = argparse.ArgumentParser(
        description="""
        WPT - Web Penetration Testing Tool v2.0
        ----------------------------------------
        Comprehensive security analysis tool for web applications.
        
        Features:
        - DNS enumeration and subdomain discovery
        - SSL/TLS configuration analysis
        - WAF detection
        - API endpoint discovery
        - JavaScript security analysis
        - Cookie security analysis
        - Form input validation testing
        
        Example usage:
            python3 -m wpt.cli example.com
            python3 -m wpt.cli https://example.com -v
            python3 -m wpt.cli example.com -o report.html -f html
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("url", help="Target URL or domain to scan")
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Number of threads for concurrent checks (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "-o", "--output", type=str, help="Save report to specified file"
    )
    parser.add_argument(
        "-f",
        "--format",
        type=str,
        default="console",
        choices=["console", "txt", "json", "html", "csv"],
        help="Output format (default: console)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )

    # Show help if no arguments
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    try:
        # Create and run scanner using context manager for proper cleanup
        with WebScanner(
            args.url, threads=args.threads, verbose=args.verbose, timeout=args.timeout
        ) as scanner:
            # Run the scan
            scanner.scan()

            # Generate report
            scanner.generate_report(output_file=args.output, output_format=args.format)

    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Scan failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

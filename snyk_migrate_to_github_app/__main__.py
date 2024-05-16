"""
Main execution point for the Snyk Migrate to GitHub App tool.
"""

import sys

from snyk_migrate_to_github_app import main


if __name__ == "__main__":
    try:
        main.run()
    except ValueError as exc:
        print(f"Failed to migrate targets: {exc}")
        sys.exit(1)

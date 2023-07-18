# GitHub Advanced Security config check

This action checks the configuration of GitHub Advanced Security features.
Code scanning, secret scanning, and dependabot need to be enabled for the repository.

## Example usage

```yaml
name: "GHAS check"

on:
  push:
    branches: [ master ]
  pull_request:
    branches: [ master ]
  schedule:
     - cron: '*/5 * * * *'
permissions:
  actions: read
  contents: read
  security-events: read
  issues: write

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v2
        # Get full history for spotless ratchetFrom
        with:
          fetch-depth: 0
      - uses: github/codeql-action/config-check@v1
        with:
          # The number of Code Scanning alerts where the action should fail. Defaults to 30.
          code_scanning_alerts_gate: '30'
          # The number of Dependabot Scanning alerts where the action should fail. Defaults to 30.
          dependabot_scanning_alerts_gate: '30'
          # The number of Secret Scanning alerts where the action should fail. Defaults to 30.
          secret_scanning_alerts_gate: '30'
          # If true, the action will create an issue in this repository with the results of the check. Defaults to false.
          issue: 'false'
          # Debug mode. Defaults to false.
          debug: 'false'
          # The GitHub token to use for authentication. Defaults to the current token.
          token: ${{ secrets.GITHUB_TOKEN }}
```
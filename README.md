# Mole: Advanced Passive Subdomain Enumerator

Mole is a powerful Python tool for passive subdomain enumeration. It aggregates results from multiple public and commercial sources, supports batch and filtered queries, and offers flexible output options for automation and reporting.

## Features

- Queries multiple sources: crt.sh, AlienVault OTX, SecurityTrails, certspotter, hackertarget, threatcrowd, wayback machine, bufferover.run, virustotal
- Batch mode: Read domains from stdin for bulk enumeration
- Filtering: Regex or wildcard filtering of subdomains (`--filter`)
- Output: Save results to file, print to stdout, or output as JSON (`--json`)
- Verbose mode for debugging and progress
- Timeout control for HTTP requests
- Summary report after execution
- Robust error handling

## Requirements

- Python 3.7+
- `requests` library

## Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/Av7danger/mole.git
   cd mole
   ```

2. Install dependencies:

   ```sh
   pip install -r requirements.txt
   ```

## Usage

### Basic

```sh
python subenum.py example.com
```

### Batch mode (multiple domains)

```sh
type domains.txt | python subenum.py --stdin
```

### Save output to a file

```sh
python subenum.py example.com -o results.txt
```

### JSON output

```sh
python subenum.py example.com --json
```

### Filter subdomains (wildcard or regex)

```sh
python subenum.py example.com --filter 'dev*'
python subenum.py example.com --filter '.*test.*'
```

### Use API keys (for more results from some sources)

Set environment variables or use CLI flags:

- `SECURITYTRAILS_KEY` for SecurityTrails
- `VT_API_KEY` for VirusTotal

Example:

```sh
python subenum.py example.com --securitytrails-key YOUR_KEY --virustotal-key YOUR_KEY
```

### Verbose mode

```sh
python subenum.py example.com --verbose
```

## License

MIT

## Author

Av7danger

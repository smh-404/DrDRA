# Dr DRA (Domain Registration Alerts)

**Dr DRA** is a domain monitoring tool that analyzes newly registered domain (NRD) lists to detect suspicious domain names that may impersonate legitimate brands. It combines multiple detection techniques—including regex pattern matching, typosquatting mutations, and Levenshtein distance analysis—to identify potentially malicious or lookalike domains as soon as they are registered.

## Features

- 📦 **Automatic Download**: Retrieves the latest daily NRD ZIP archive from WhoisDS (free daily download).
- 🧪 **Regex-Based Matching**: Uses customizable pattern matching to flag domain lookalikes.
- 🌀 **Typosquatting Detection**: Generates common typosquatting variants for a given domain name (e.g., character swaps, omissions, homoglyphs).
- 📏 **Levenshtein Distance Analysis**: Flags domains with small edit distances from your legitimate brand name.
- 🔁 **Interactive Mode**: Supports multiple domain lookups per run.
- 💡 **Fallback Logic**: If today's NRD file is unavailable, automatically checks yesterday’s list.

## Usage
You'll be prompted to enter a legitimate domain (e.g., microsoft.com). The tool will analyze the most recent list of newly registered domains and report potential threats.
Type exit to quit the session.


Example:

Enter your legitimate domain (or type 'exit' to quit): microsoft.com

🚨 Detected suspicious domains related to 'microsoft.com':
  - micros0ft-login.net
  - rnicrosoft.com
  - microsoftupdate.org

## Detection Techniques

Dr DRA leverages three detection layers:

    Regex Patterns: Matches variants like microsoftlogin.com, secure-microsoft.net, etc.

    Typosquatting Variants: Simulates character swaps, duplication, homoglyphs, and more.

    Levenshtein Distance: Detects domain names that are within a small edit distance (default ≤ 2) from the original.

Customization

    Modify the regex patterns in build_regex_patterns() to tailor matches.

    Adjust Levenshtein threshold in search_domains() for stricter or looser matching.

    Extend typosquatting rules in generate_typosquatting_domains().

## License

This project is provided under the MIT License.

## Disclaimer

This tool relies on publicly available NRD data. It is not a substitute for a commercial brand protection service but can support proactive monitoring of potential impersonation threats for free.

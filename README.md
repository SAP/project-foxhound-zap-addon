[![REUSE status](https://api.reuse.software/badge/github.com/SAP/project-foxhound-zap-addon)](https://api.reuse.software/info/github.com/SAP/project-foxhound-zap-addon)

# Project Foxhound ZAP AddOn

## About this project

An addon to integrate [Project Foxhound](https://github.com/SAP/project-foxhound) with the [Zed Attack Proxy](https://www.zaproxy.org/) (ZAP), enabling precision detection of client-side injection vulnerabilities during dynamic testing.

## Requirements and Setup

### Prerequisites

To set up, make sure you have a recent Java SDK (17 or 21) installed on your system.

### Build

This AddOn ships with the gradle wrapper, so you just run:

For Linux systems:
```bash
./gradlew assemble
```

For Windows systems:
```PowerShell
.\gradlew.bat assemble
```

### Installation

The build stage will produce a zap addon file in the ```build/zapAddOn/bin``` directory.
This file can be installed by opening ZAP:

```
File -> Load Add-on File -> Choose ZAP file
```

## Support, Feedback, Contributing

This project is open to feature requests/suggestions, bug reports etc. via [GitHub issues](https://github.com/SAP/project-foxhound-zap-addon/issues). Contribution and feedback are encouraged and always welcome. For more information about how to contribute, the project structure, as well as additional contribution information, see our [Contribution Guidelines](CONTRIBUTING.md).

## Security / Disclosure
If you find any bug that may be a security problem, please follow our instructions at [in our security policy](https://github.com/SAP/project-foxhound-zap-addon/security/policy) on how to report it. Please do not create GitHub issues for security-related doubts or problems.

## Code of Conduct

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone. By participating in this project, you agree to abide by its [Code of Conduct](https://github.com/SAP/.github/blob/main/CODE_OF_CONDUCT.md) at all times.

## Licensing

Copyright 2026 SAP SE or an SAP affiliate company and project-foxhound-zap-addon contributors. Please see our [LICENSE](LICENSE) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available [via the REUSE tool](https://api.reuse.software/info/github.com/SAP/project-foxhound-zap-addon).

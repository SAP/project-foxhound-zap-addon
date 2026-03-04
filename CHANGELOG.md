# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

### Added
- Comprehensive JavaHelp documentation (11 help pages)
  - Getting Started guide for new users
  - Troubleshooting guide with common issues and solutions
  - Core concepts guide explaining taint tracking, sources, and sinks
  - Options configuration guide
  - Foxhound Panel UI guide
  - Vulnerability alerts reference (DOM XSS, Stored XSS, CSRF)
  - Database persistence and cache architecture documentation
  - Selenium integration guide
- Internationalization infrastructure (support for 30+ languages via JavaHelp framework)
- Search index with 40+ keywords for help system
- Table of contents with hierarchical navigation

## [0.1.0] - 2025-12-08

### Added
- Initial release of Foxhound ZAP Add-on
- Taint flow tracking integration with Project Foxhound browser
- FoxhoundExportServer HTTP endpoint for receiving taint data (default port 55676)
- TaintInfoStore with two-tier storage architecture:
  - Tier 1: LRU cache in memory (default 1000 entries, configurable 1-100,000)
  - Tier 2: HSQLDB persistence across sessions with normalized schema
- Database schema with 4 normalized tables:
  - TAINT_INFO: Main taint flow records
  - TAINT_OPERATION: Individual operations in flow chains
  - TAINT_RANGE: Tainted substrings with position information
  - TAINT_FLOW: Operation sequences linking ranges to operations
- Write-through cache strategy with lazy loading from database
- Graceful degradation to memory-only mode if database unavailable
- Vulnerability detection checks:
  - DOM XSS detection (Plugin ID: 40100, Risk: HIGH)
  - Stored XSS detection (Plugin ID: 40101, Risk: HIGH)
  - CSRF detection (Plugin ID: 40102, Risk: MEDIUM)
  - General taint info alerts (Plugin ID: 40103, Risk: INFO)
- FoxhoundPanel UI with tree table display:
  - Hierarchical view (TaintInfo → TaintRange → TaintOperation)
  - Launch Foxhound browser button
  - Filter dialog for sources and sinks
  - Clear All button
  - Real-time footer counter
- FoxhoundOptions configuration panel:
  - Export server port configuration
  - Taint cache size configuration (1-100,000 entries)
  - Sources enable/disable toggles
  - Sinks enable/disable toggles
- Selenium integration:
  - Automatic foxhound-profile Firefox profile creation
  - Profile updates with taint tracking preferences (user.js)
  - Browser launch via Selenium add-on
  - Automatic proxy configuration
- Event system with FoxhoundEventPublisher:
  - TAINT_INFO_CREATED events
  - TAINT_INFO_UPDATED events
  - TAINT_INFO_CLEARED events
- Sources and sinks configuration via sourcessinks.json
- Support for 48 languages via Messages.properties files
- FoxhoundAlertHelper for automatic vulnerability alert generation
- Alert templates with OWASP references and remediation guidance

[0.1.0]: https://github.com/zaproxy/zap-extensions/releases/foxhound-v0.1.0

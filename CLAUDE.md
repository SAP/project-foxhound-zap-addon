# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a ZAP (Zed Attack Proxy) add-on that integrates Project Foxhound, a modified Firefox browser that tracks client-side data flows for security testing. The add-on receives taint flow data from Foxhound browser instances, analyzes them for vulnerabilities (XSS, CSRF, etc.), and raises alerts within ZAP.

## Build Commands

Build the add-on:
```bash
./gradlew assemble
```

Run all checks (tests + linting):
```bash
./gradlew check
```

Run tests only:
```bash
./gradlew test
```

Run code formatting (Google Java Format AOSP style):
```bash
./gradlew spotlessApply
```

Check code formatting:
```bash
./gradlew spotlessCheck
```

Build and run all verification:
```bash
./gradlew build
```

The built add-on file will be in: `build/zapAddOn/bin/`

## Requirements

- Java SDK 17 or 21 (SAP Machine is used in CI)
- Gradle wrapper is included in the repository

## Architecture

### Core Data Flow

1. **FoxhoundExportServer** - HTTP server (default port configured in FoxhoundOptions) that receives taint flow data from Foxhound browser instances via POST requests
2. **TaintDeserializer** - Parses JSON taint flow data from Foxhound into TaintInfo objects
3. **TaintInfoStore** - In-memory concurrent storage for taint flows, publishes events when taint info is added
4. **FoxhoundAlertHelper** - Event consumer that analyzes taint flows and raises ZAP alerts based on vulnerability checks
5. **FoxhoundPanel** - UI panel displaying taint flows in a tree table structure

### Extension Lifecycle

The main extension class is `ExtensionFoxhound`, which:
- Depends on ExtensionNetwork and ExtensionSelenium
- Starts the export server on initialization
- Creates a Selenium profile configured with source/sink preferences for Foxhound
- Registers UI components (launch button, status panel, main panel)

### Taint Flow Model

**TaintInfo** represents a complete taint flow with:
- Sources: Where tainted data originates (location.hash, document.cookie, etc.)
- Sink: Where tainted data is used dangerously (eval, innerHTML, etc.)
- TaintRanges: Specific substrings of the sink data and their flow chains
- TaintOperation: Individual operation in the flow with location info

**Source/Sink Configuration**: Defined in `src/main/resources/.../sourcessinks.json` and loaded into FoxhoundConstants. Sources and sinks have tags (URL, XSS, STORAGE, etc.) used by vulnerability checks.

### Vulnerability Detection

Base class **FoxhoundBaseCheck** provides the pattern for vulnerability checks:
- Implements shouldAlert() to match source/sink combinations
- Subclasses define required sources/sinks for specific vulnerabilities

Current checks:
- **FoxhoundXssCheck** - DOM-based XSS (sources: URL/INPUT, sinks: XSS-tagged)
- **FoxhoundStoredXssCheck** - Stored XSS (sources: STORAGE, sinks: XSS-tagged)
- **FoxhoundCsrfCheck** - CSRF vulnerabilities
- **FoxhoundTaintInfoCheck** - General taint flow info

### Event System

Uses ZAP's EventBus for decoupled communication:
- **FoxhoundEventPublisher** publishes: TAINT_INFO_CREATED, TAINT_INFO_UPDATED, TAINT_INFO_CLEARED
- Consumers: FoxhoundAlertHelper (raises alerts), FoxhoundPanel (updates UI)

### Selenium Integration

**FoxhoundSeleniumProfile** writes Firefox preferences to configure which sources/sinks are tracked:
- Creates/updates a profile named "foxhound-profile"
- Writes user.js with tainting preferences based on FoxhoundOptions
- Sets export URL to point to FoxhoundExportServer

## Key Package Structure

- `alerts/` - Vulnerability check implementations
- `config/` - Configuration, constants, Selenium profile management
- `db/` - TaintInfoStore and filtering
- `taint/` - Core taint flow data model and deserialization
- `ui/` - Swing UI components for displaying taint flows

## Testing Notes

Tests use JUnit 5 (Jupiter). Single test execution:
```bash
./gradlew test --tests SourceAndSinkTypeTest
```

## ZAP Add-on Specifics

- Add-on ID: "foxhound"
- Status: ALPHA
- Plugin IDs: 40100-40103 (documented in ZAP scanner registry)
- Implements PluginPassiveScanner for passive scanning hooks
- Implements ExampleAlertProvider for alert templates
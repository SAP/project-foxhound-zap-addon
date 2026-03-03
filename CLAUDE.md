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
3. **TaintInfoStore** - Persistent storage for taint flows with two-tier architecture:
   - **Tier 1**: Hot LRU cache in memory (default 1000 entries, configurable)
   - **Tier 2**: Complete dataset in HSQLDB for persistence across sessions
   - Write-through cache: All additions immediately persisted to database
   - Lazy loading: Items loaded from database on-demand when not in cache
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

### Database Persistence

**TaintInfoTable** extends ParosAbstractTable to persist taint flows using normalized SQL tables:
- **Schema**: 4 tables (TAINT_INFO, TAINT_OPERATION, TAINT_RANGE, TAINT_FLOW)
- **Foreign keys**: CASCADE DELETE maintains referential integrity
- **Indexes**: Optimized for timestamp, sink name, and operation queries
- **Serialization**: Pure SQL storage (no JSON) - all TaintInfo fields stored in normalized relational tables

**TaintInfoStore** implements DatabaseListener for lifecycle management:
- `init()`: Registers table and store as database listeners
- `databaseOpen()`: Loads max ID and existing data after database is ready
- Gracefully degrades to in-memory mode if database unavailable
- LRU eviction when cache size exceeds `foxhound.taint.cacheSize` (default 1000)

**Implementation Details**:
- Write-through cache: All adds immediately persisted via `TaintInfoTable.insert()`
- Lazy loading: Cache misses trigger `TaintInfoTable.read()` from database
- Transaction support: Inserts use commit/rollback for data integrity
- Testing: `testConnection` field enables unit testing outside ZAP infrastructure

## Key Package Structure

- `alerts/` - Vulnerability check implementations
- `config/` - Configuration, constants, Selenium profile management
- `db/` - Database persistence layer:
  - `TaintInfoTable.java` - ParosAbstractTable implementation with normalized SQL schema
  - `TaintInfoStore.java` - LRU cache + database storage with DatabaseListener integration
  - `TaintInfoFilter.java` - Filtering logic for queries
  - `CachedTaintInfo.java` - LRU cache entry wrapper with access time tracking
- `taint/` - Core taint flow data model and deserialization
- `ui/` - Swing UI components for displaying taint flows

## Testing Notes

Tests use JUnit 5 (Jupiter). Single test execution:
```bash
./gradlew test --tests SourceAndSinkTypeTest
```

Database tests:
- `TaintInfoTableTest` - Tests normalized SQL table operations (12 tests)
- `TaintInfoStoreTest` - Tests caching and store behavior (13 tests)
- Tests use in-memory HSQLDB for isolation
- `TaintInfoTable.testConnection` enables testing outside ZAP infrastructure

## Important Implementation Patterns

### Database Lifecycle
1. **Initialization**: `ExtensionFoxhound.hook()` calls `TaintInfoStore.init(Database)`
2. **Registration**: Store registers both `TaintInfoTable` and itself as database listeners
3. **Reconnect**: ZAP calls `TaintInfoTable.reconnect(Connection)` to create tables and prepare statements
4. **Data Loading**: ZAP calls `TaintInfoStore.databaseOpen(DatabaseServer)` to load persisted data
5. **Graceful Degradation**: If database unavailable, store operates in memory-only mode

### Adding New Database Fields
To add a new field to TaintInfo persistence:
1. Add column to CREATE TABLE statement in `TaintInfoTable.createTables()`
2. Update INSERT statement in `prepareStatements()`
3. Add setter in `TaintInfoTable.insert()` method
4. Add getter in `TaintInfoTable.read()` method
5. Update tests to include new field

### LRU Cache Tuning
Configure cache size in `FoxhoundOptions`:
- Default: 1000 entries
- Property key: `foxhound.taint.cacheSize`
- Eviction: Least recently accessed items removed when cache exceeds max size

## ZAP Add-on Specifics

- Add-on ID: "foxhound"
- Status: ALPHA
- Plugin IDs: 40100-40103 (documented in ZAP scanner registry)
- Implements PluginPassiveScanner for passive scanning hooks
- Implements ExampleAlertProvider for alert templates
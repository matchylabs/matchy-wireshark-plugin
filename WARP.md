# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

matchy-wireshark-plugin is a Wireshark plugin written in Rust that provides real-time threat intelligence matching for packet analysis. The plugin acts as a postdissector, processing packets after normal Wireshark dissection to match IPs and domains against threat databases.

## Build and Development Commands

### Building
```bash
# Debug build
cargo build

# Release build (optimized for performance)
cargo build --release
```

The compiled plugin will be located at:
- **macOS**: `target/release/libmatchy_wireshark.dylib`
- **Linux**: `target/release/libmatchy_wireshark.so`

### Testing
```bash
# Run all unit tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test module
cargo test threats::tests
```

### Code Quality
```bash
# Check for common issues
cargo clippy -- -D warnings

# Format code
cargo fmt

# Check formatting without applying
cargo fmt -- --check
```

### Installation
After building, copy the plugin to your Wireshark plugins directory:

**macOS:**
```bash
cp target/release/libmatchy_wireshark.dylib ~/.local/lib/wireshark/plugins/
```

**Linux:**
```bash
cp target/release/libmatchy_wireshark.so ~/.local/lib/wireshark/plugins/
```

## Architecture

### Plugin Flow
1. **Plugin Loading**: `plugin_register()` is called by Wireshark when the plugin loads
2. **Postdissector Registration**: Registers the postdissector to process every packet
3. **Database Loading**: User loads a `.mxy` threat database via Wireshark preferences
4. **Packet Processing**: For each packet:
   - Extract source/destination IPs and domain names
   - Query the matchy database for threat intelligence
   - Add custom fields to Wireshark's packet tree
   - Apply threat-level coloring (red=critical, orange=high, yellow=medium)

### Module Organization

- **`lib.rs`**: Plugin entry point, FFI exports, global database management
  - FFI functions exported for Wireshark C API
  - Global `THREAT_DB` mutex holding the loaded threat database
  - Version and plugin metadata constants

- **`postdissector.rs`**: Wireshark postdissector implementation
  - Registers the postdissector with Wireshark
  - Main packet processing logic (currently skeleton)
  - Extracts IPs/domains and queries the database

- **`threats.rs`**: Threat matching and packet colorization
  - `ThreatLevel` enum: Critical, High, Medium, Low, Unknown
  - `ThreatData` struct: Parsed threat intelligence data
  - Wireshark color mappings for threat levels
  - JSON parsing from matchy database results

- **`display_filter.rs`**: Custom display filter expressions
  - Registers custom Wireshark filter fields (e.g., `matchy.threat_detected`)
  - Filter expression evaluation (currently skeleton)

### FFI Layer

The plugin uses Rust FFI to interface with Wireshark's C API:
- `#[no_mangle]` exports for C visibility
- `extern "C"` functions for C calling convention
- Uses `libc` types (`c_char`, `c_int`, `c_void`)
- Compiled as `cdylib` for dynamic loading

### Thread Safety

The threat database is stored in a `static Mutex<Option<Arc<matchy::Database>>>`:
- Thread-safe access across Wireshark's multi-threaded packet processing
- `Arc` allows shared ownership without copying the large database
- Database loaded once, read many times

## Dependencies

### External Libraries
- **matchy**: Core threat database library (from GitHub, main branch)
  - Provides `.mxy` database format reading
  - IP trie for CIDR matching
  - Glob pattern matching for domains
  - Sub-millisecond lookups

- **libc**: C FFI types and functions
- **serde_json**: JSON parsing for threat metadata

### Build Configuration
- **crate-type**: `cdylib` (C-compatible dynamic library)
- **LTO enabled**: For maximum performance in release builds
- **Debug symbols included**: Even in release builds for profiling

## Development Status

**Current State**: Early skeleton implementation

**Implemented**:
- Basic plugin structure and FFI exports
- ThreatLevel enum with Wireshark color mappings
- ThreatData JSON parsing
- Database loading infrastructure
- Module organization

**TODO (marked in code)**:
- Wireshark C API bindings (calling into Wireshark functions)
- Packet processing logic (IP/domain extraction)
- Display filter registration and evaluation
- Actual threat lookups using matchy database
- Packet tree field additions
- Integration tests with real Wireshark

## Wireshark Plugin Development

### Key Concepts
- **Postdissector**: Runs after normal packet dissection, can add custom fields
- **Display Filters**: Custom filter expressions like `matchy.threat_detected`
- **Packet Tree**: Hierarchical display of packet data in Wireshark UI
- **TVB**: Wireshark's "Testy Virtual Buffer" for packet data access

### Expected Display Filters
Once implemented, analysts will be able to filter packets using:
```
matchy.threat_detected                 # Any threat match
matchy.level == "critical"             # Specific threat level
matchy.category == "malware"           # Specific category
matchy.level == "high" && tcp.port == 443  # Combined filters
```

### Performance Requirements
- **Lookup time**: <1ms per packet (no capture degradation)
- **Memory usage**: <50MB per Wireshark process
- **Zero-copy**: Memory-mapped threat database, no data copying

## Testing Strategy

### Unit Tests
Each module has inline tests:
- `threats.rs`: ThreatLevel conversions, JSON parsing, color mappings
- Test with: `cargo test`

### Integration Testing
Will require:
1. Building sample `.mxy` threat databases
2. Loading in Wireshark and capturing traffic
3. Verifying correct threat detection and display
4. Performance profiling under load

### Test Database Creation
Use the matchy CLI to build test databases:
```bash
# Create from CSV
matchy build threats.csv -o test.mxy --format csv

# Example CSV format:
# entry,threat_level,category,source
# 1.2.3.4,high,malware,abuse.ch
# *.evil.com,critical,phishing,urlhaus
```

## Code Style

- Follow standard Rust conventions (enforced by `cargo fmt`)
- Use meaningful variable names (not single letters except in small scopes)
- Add doc comments (`///`) for public items
- Use `TODO:` comments for incomplete implementations
- Prefer explicit error handling over `unwrap()`

## Related Resources

- [Matchy Core Library](https://github.com/matchylabs/matchy)
- [Wireshark Plugin Development](https://www.wireshark.org/docs/wsdg_html_chunked/)
- [Wireshark FFI in Rust](https://doc.rust-lang.org/nomicon/ffi.html)

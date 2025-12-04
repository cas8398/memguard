# 🛡️ MemGuard

![Android](https://img.shields.io/badge/Android-Supported-brightgreen)
![iOS](https://img.shields.io/badge/iOS-Not%20Tested-lightgrey)
![Windows](https://img.shields.io/badge/Windows-Not%20Tested-lightgrey)
![macOS](https://img.shields.io/badge/macOS-Not%20Tested-lightgrey)
![Linux](https://img.shields.io/badge/Linux-Not%20Tested-lightgrey)

**Hybrid secure storage for Flutter with zero-leak memory protection and hardware-backed encryption.**

MemGuard combines **ultra-fast Rust FFI memory storage** with **hardware-backed platform security** (Android KeyStore, iOS Keychain) to give you the best of both worlds: blazing performance for ephemeral data and military-grade protection for persistent secrets.

---

## ✨ Features

### 🚀 Dual Storage Modes

**Memory Storage (Rust FFI)**

- ⚡ **Zero-copy direct access** — no Dart VM overhead
- 🔥 **Ephemeral by design** — data vanishes on app close
- 🧠 **Protected memory** — explicit zeroing prevents leaks
- 🔐 **Optional encryption** — AES-256-GCM in Rust
- 🎯 **Perfect for:** Session tokens, API keys, temporary credentials

**Device Secure Storage (Platform Channels)**

- 🔒 **Hardware-backed encryption** — Android KeyStore (StrongBox/TEE)
- 💾 **Persistent across restarts** — survives app kills
- 🛡️ **Zero platform channel leaks** — only boolean flags transmitted
- 🗄️ **Disk-backed with Rust cache** — fast reads after first access
- 🎯 **Perfect for:** User credentials, refresh tokens, sensitive settings

### 🔐 Zero-Leak Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR DART CODE                           │
│         • Never touches sensitive data directly            │
│         • Only receives boolean status flags               │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
         ┌─────────────────────┐
         │   MemGuard Plugin   │  ← You are here
         │   (Dart API Layer)  │
         └─────────┬───────────┘
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
┌──────────────────┐  ┌────────────────────┐
│   Rust FFI       │  │  Platform Channel  │
│  (Memory Cache)  │  │  (Kotlin/Swift)    │
│                  │  │                    │
│ • Direct access  │  │ • KeyStore/Keychain│
│ • Zero-copy      │  │ • Encrypted files  │
│ • Protected mem  │  │ • No plaintext     │
└──────────────────┘  └────────────────────┘
```

**Critical Design Decision:**

- **Memory mode**: Data lives ONLY in Rust — Dart never sees plaintext
- **Secure mode**: Platform channels return `true/false/null` — Dart fetches from Rust cache
- **Result**: Zero attack surface in Dart VM and platform channels

---

## 🚀 Quick Start

### Installation

```yaml
dependencies:
  memguard: ^1.0.0
```

### Basic Usage

```dart
import 'package:memguard/memguard.dart';

void main() {
  runApp(
    MemGuard(
      // Choose your storage mode
      storageType: StorageType.memory, // or StorageType.deviceSecure

      // Memory options (for memory mode)
      enableEncryptionMemory: true,
      autoCleanupMemory: true,
      cleanupIntervalMemory: Duration(minutes: 10),

      // Debug logging
      showLog: true,

      child: MyApp(),
    ),
  );
}

// Then use anywhere in your app:
class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: HomePage(),
    );
  }
}

class HomePage extends StatelessWidget {
  Future<void> saveToken() async {
    // Store securely
    await MemGuardStatic.store('auth_token', 'super_secret_jwt');

    // Retrieve
    final token = await MemGuardStatic.retrieve('auth_token');
    print('Token: $token');

    // Check existence
    final exists = await MemGuardStatic.contains('auth_token');

    // Delete
    await MemGuardStatic.delete('auth_token');
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('MemGuard Demo')),
      body: Center(
        child: ElevatedButton(
          onPressed: saveToken,
          child: Text('Test Secure Storage'),
        ),
      ),
    );
  }
}
```

---

## 📖 API Reference

### Storage Operations

```dart
// Store data
await MemGuardStatic.store('key', 'value');

// Retrieve data
String? value = await MemGuardStatic.retrieve('key');

// Check if key exists
bool exists = await MemGuardStatic.contains('key');

// Delete key
await MemGuardStatic.delete('key');

// Get storage statistics
Map<String, dynamic> stats = await MemGuardStatic.getStats();

// Cleanup memory (memory mode only)
MemGuardStatic.cleanupMemory();

// Cleanup all storage
MemGuardStatic.cleanupAll();
```

### Advanced: Zero-Copy Operations (Memory Mode Only)

For maximum performance, access data directly in Rust memory without copying to Dart:

```dart
// Perform cryptographic operations without copying to Dart
final signature = await MemGuardStatic.performSecureOperation<String>(
  'private_key',
  (dataPtr, length) {
    // Direct pointer access — zero copies!
    final bytes = dataPtr.asTypedList(length);

    // Perform operation (e.g., sign with private key)
    final signature = yourCryptoLib.sign(bytes, message);

    return signature;
    // Buffer automatically zeroed after this scope
  },
);
```

**Use cases:**

- Cryptographic signing without key exposure
- Hash computation on sensitive data
- Encryption/decryption with in-memory keys
- Any operation where data must never touch Dart heap

---

## 🎯 Storage Mode Comparison

| Feature          | Memory Storage        | Device Secure Storage  |
| ---------------- | --------------------- | ---------------------- |
| **Speed**        | ⚡ Instant (Rust FFI) | 🐇 Fast (disk + cache) |
| **Persistence**  | ❌ Ephemeral          | ✅ Survives restarts   |
| **Encryption**   | Optional (Rust AES)   | ✅ Hardware-backed     |
| **Auto-cleanup** | ✅ Configurable       | ❌ Manual only         |
| **Zero-copy**    | ✅ Yes                | ❌ No                  |
| **Best for**     | Session data          | Long-term secrets      |

### When to Use Memory Storage

```dart
MemGuard(
  storageType: StorageType.memory,
  enableEncryptionMemory: true,
  autoCleanupMemory: true,
  cleanupIntervalMemory: Duration(minutes: 5),
  child: MyApp(),
)
```

✅ **Perfect for:**

- Session tokens (expire on app close)
- Temporary API keys
- In-flight credentials
- Crypto operations (use `performSecureOperation`)
- Any data that shouldn't persist

### When to Use Device Secure Storage

```dart
MemGuard(
  storageType: StorageType.deviceSecure,
  child: MyApp(),
)
```

✅ **Perfect for:**

- User login credentials
- OAuth refresh tokens
- Biometric authentication keys
- App settings with sensitive data
- Anything that must survive app restart

---

## 🔧 Configuration Options

### Memory Storage Configuration

```dart
MemGuard(
  storageType: StorageType.memory,

  // Enable AES-256-GCM encryption in Rust
  enableEncryptionMemory: true,

  // Auto-cleanup on app background/close
  autoCleanupMemory: true,

  // How often to run cleanup (if auto enabled)
  cleanupIntervalMemory: Duration(minutes: 10),

  // Enable debug logging
  showLog: true,

  child: MyApp(),
)
```

### Device Secure Storage Configuration

```dart
MemGuard(
  storageType: StorageType.deviceSecure,

  // Enable Rust cache for faster reads (recommended)
  enableEncryptionMemory: true,

  // Enable debug logging
  showLog: true,

  child: MyApp(),
)
```

---

## 🛡️ Security Features

### What MemGuard Protects Against

✅ **Memory Dumps** — Sensitive data never stored in Dart VM heap  
✅ **Platform Channel Interception** — Only boolean flags transmitted  
✅ **Heap Inspection** — Rust memory is protected and zeroed  
✅ **Data Tampering** — GCM authentication tags verify integrity  
✅ **Key Extraction** — Hardware-backed keys never leave secure enclave  
✅ **Root Access** (partial) — Keys resist extraction even on rooted devices

### Attack Resistance

```dart
// ❌ BAD: Traditional secure storage
await secureStorage.write('token', 'secret'); // Plaintext in Dart heap!

// ✅ GOOD: MemGuard memory storage
await MemGuardStatic.store('token', 'secret'); // Only in Rust protected memory

// ✅ BETTER: MemGuard device secure
MemGuard(storageType: StorageType.deviceSecure, ...); // Hardware encryption + Rust cache
```

### What MemGuard Does NOT Protect Against

❌ **Physical device seizure** by sophisticated attackers  
❌ **Compromised OS/kernel** (malware with root/system privileges)  
❌ **User-authorized access** (screen recording, accessibility services)  
❌ **State-level adversaries** with hardware forensics tools

**Threat Model**: MemGuard is designed for **production app security** against common attack vectors (malware, memory dumps, network interception). It is NOT a substitute for end-to-end encryption or protection against nation-state actors.

---

## 📊 Storage Statistics

```dart
final stats = await MemGuardStatic.getStats();
print(stats);

// Memory Storage Output:
// {
//   "items_count": 5,
//   "total_size_bytes": 2048,
//   "encrypted_items": 5,
//   "platform": "android",
//   "rust_version": "1.70.0",
//   "storage_type": "memory"
// }

// Device Secure Storage Output:
// {
//   "storage_type": "hardware_backed_keystore",
//   "encryption_type": "aes_256_gcm",
//   "key_strength": "256_bit",
//   "rust_initialized": true,
//   "items_count": 3,
//   "total_size_bytes": 4096,
//   "directory_path": "/data/user/0/com.app/files/memguard_secure",
//   "timestamp": 1701234567890
// }
```

---

## 🎨 Convenience Extensions

### String Extension

```dart
// Store string directly
await "my_secret_value".storeAs('api_key');

// Works with any storage type
await "refresh_token_xyz".storeAs('refresh_token');
```

### Context Extension

```dart
class MyWidget extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    // Access MemGuard core directly
    final core = context.memguard;

    // Check initialization status
    print('Storage type: ${core.currentStorageType}');
    print('Rust ready: ${core.isRustInitialized}');

    return Container();
  }
}
```

---

## 🔄 Lifecycle Management

MemGuard automatically handles app lifecycle events:

```dart
// Memory Storage: Auto-cleanup on background
MemGuard(
  storageType: StorageType.memory,
  autoCleanupMemory: true, // ← Cleans on app pause/background
  child: MyApp(),
)

// Lifecycle events handled:
// • AppLifecycleState.paused → cleanupMemory()
// • AppLifecycleState.inactive → cleanupMemory()
// • AppLifecycleState.detached → cleanupAll()
```

Manual cleanup:

```dart
// Clean memory only (memory mode)
MemGuardStatic.cleanupMemory();

// Clean everything (all modes)
MemGuardStatic.cleanupAll();
```

---

## 🐛 Error Handling

```dart
try {
  await MemGuardStatic.store('key', 'value');
} catch (e) {
  if (e is StateError) {
    // MemGuard not initialized
    print('Initialize MemGuard first!');
  } else if (e is UnsupportedError) {
    // Feature not available (e.g., zero-copy on device secure)
    print('Operation not supported for this storage type');
  } else if (e is ArgumentError) {
    // Storage type mismatch
    print('Wrong storage type specified');
  } else {
    // Other errors (platform exceptions, etc.)
    print('Storage error: $e');
  }
}
```

Common errors:

- **`StateError: MemGuard is not initialized`** — Wrap your app in `MemGuard` widget
- **`UnsupportedError: Secure buffer operations only available for memory storage`** — Use `StorageType.memory` for zero-copy
- **`ArgumentError: Requested storage type does not match`** — Don't mix storage types in same session

---

## 📱 Platform Support

| Platform | Memory Storage | Device Secure | Status           |
| -------- | -------------- | ------------- | ---------------- |
| Android  | ✅ Full        | ✅ Full       | Production Ready |
| iOS      | ⚠️ Untested    | ⚠️ Untested   | Needs Testing    |
| Windows  | ⚠️ Untested    | ⚠️ Untested   | Needs Testing    |
| macOS    | ⚠️ Untested    | ⚠️ Untested   | Needs Testing    |
| Linux    | ⚠️ Untested    | ⚠️ Untested   | Needs Testing    |

### Android Requirements

- **Minimum**: API 23 (Android 6.0 Marshmallow)
- **Recommended**: API 28+ (Android 9.0 Pie) for StrongBox support

---

## 🏗️ Architecture

MemGuard is built on top of [**MemGuard Core**](https://github.com/cas8398/memguard_core) — the native Rust + Kotlin foundation that powers the zero-leak security model.

**Stack:**

- **Dart Layer** (this plugin): High-level Flutter API
- **Rust FFI**: Protected memory allocation and cryptography
- **Kotlin Platform**: Android KeyStore integration and encrypted file I/O
- **Native Libraries**: Compiled `.so` binaries for ARM/x86

See the [MemGuard Core README](https://github.com/cas8398/memguard_core) for low-level implementation details.

---

## 🧪 Testing

```dart
// Example test
void main() {
  test('Memory storage lifecycle', () async {
    MemGuardStatic.initMemoryStorage(
      enableEncryptionMemory: true,
      autoCleanupMemory: false,
      cleanupIntervalMemory: Duration(minutes: 10),
    );

    await MemGuardStatic.store('test_key', 'test_value');

    final value = await MemGuardStatic.retrieve('test_key');
    expect(value, 'test_value');

    await MemGuardStatic.delete('test_key');

    final deleted = await MemGuardStatic.retrieve('test_key');
    expect(deleted, isNull);
  });
}
```

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Contribution

- [ ] iOS/macOS platform implementation
- [ ] Windows/Linux platform implementation
- [ ] Additional encryption algorithms
- [ ] Performance benchmarks
- [ ] Integration tests
- [ ] Documentation improvements

---

## 🙏 Acknowledgments

Built with:

- **Rust FFI** for memory-safe protected storage
- **Android KeyStore** for hardware-backed encryption
- **flutter_fastlog** for high-performance logging
- **MemGuard Core** for the native foundation

---

## ⚠️ Security Notice

MemGuard implements defense-in-depth secure storage with zero-leak architecture. However, **no client-side storage is absolutely secure**. Always:

- ✅ Validate critical operations server-side
- ✅ Use certificate pinning for network requests
- ✅ Implement request signing for API calls
- ✅ Rotate sensitive credentials regularly
- ✅ Enable biometric authentication when available

For high-security applications, combine MemGuard with additional layers of protection (HSM, remote attestation, etc.).

---

## 📚 Related Projects

- [MemGuard Core](https://github.com/cas8398/memguard_core) - Native Rust + Kotlin foundation
- [flutter_secure_storage](https://pub.dev/packages/flutter_secure_storage) - Alternative secure storage (single mode)
- [flutter_keychain](https://pub.dev/packages/flutter_keychain) - Platform keychain access

---

## 💬 Support

- 📖 [Documentation](https://memguard.dev/docs)
- 💡 [Examples](https://github.com/yourusername/memguard/tree/main/example)
- 🐛 [Issue Tracker](https://github.com/cas8398/memguard/issues)
- 💬 [Discussions](https://github.com/cas8398/memguard/discussions)

---

**Made with 🛡️ by Cahyanudien Aziz Saputra**

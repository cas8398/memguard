/// 🛡️ MemGuard - Hybrid Storage Protection
library memguard;

import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'src/logger.dart';
import 'package:flutter_fastlog/flutter_fastlog.dart';

/// 🗃️ Storage Types
enum StorageType {
  /// 🔥 Memory only - Uses Rust FFI (fast, ephemeral)
  memory,

  /// 🔐 Device secure storage - Uses platform channels (KeyStore/KeyChain)
  deviceSecure,
}

/// 🎯 Main MemGuard Wrapper Widget
class MemGuard extends StatefulWidget {
  final Widget child;
  final StorageType storageType;
  final bool enableEncryptionMemory;
  final bool autoCleanupMemory;
  final Duration cleanupIntervalMemory;
  final bool showLog;

  const MemGuard({
    super.key,
    required this.child,
    this.storageType = StorageType.memory,
    this.enableEncryptionMemory = true,
    this.autoCleanupMemory = true,
    this.cleanupIntervalMemory = const Duration(minutes: 10),
    this.showLog = false,
  });

  @override
  State<MemGuard> createState() => _MemGuardState();
}

/// 🔧 MemGuard State
class _MemGuardState extends State<MemGuard> with WidgetsBindingObserver {
  late final MemGuardCore _memGuardCore;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);

    // Initialize logger
    logger();

    _memGuardCore = MemGuardCore.instance;

    // ALWAYS initialize Rust FFI for memory safety
    _memGuardCore.initRust(
      enableEncryptionMemory: widget.enableEncryptionMemory,
      autoCleanupMemory: widget.autoCleanupMemory,
      cleanupIntervalMemory: widget.cleanupIntervalMemory,
      showLog: widget.showLog,
    );

    if (widget.storageType != StorageType.memory) {
      // Initialize platform channels for persistent/secure storage
      _memGuardCore.initPlatform(
        storageType: widget.storageType,
        enableEncryptionMemory: widget.enableEncryptionMemory,
        showLog: widget.showLog,
      );
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _memGuardCore.cleanupAll();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (!widget.autoCleanupMemory || widget.storageType != StorageType.memory) {
      return;
    }

    switch (state) {
      case AppLifecycleState.paused:
      case AppLifecycleState.inactive:
        if (widget.storageType == StorageType.memory) {
          _memGuardCore.cleanupMemory();
        }
        break;
      case AppLifecycleState.detached:
        _memGuardCore.cleanupAll();
        break;
      default:
        break;
    }
  }

  @override
  Widget build(BuildContext context) {
    return widget.child;
  }
}

/// 🎮 Core MemGuard Engine
class MemGuardCore {
  static final MemGuardCore instance = MemGuardCore._();

  // Storage type being used
  StorageType? _currentStorageType;

  // Rust FFI (for memory storage only)
  DynamicLibrary? _rustLib;
  bool _rustInitialized = false;

  // Platform channels (for persistent/secure storage)
  static const String _channelName = 'com.memguard/storage';
  final MethodChannel _platformChannel = const MethodChannel(_channelName);

  // Common
  bool _showLog = false;

  MemGuardCore._();

  /// 🚀 Initialize Rust FFI (Memory storage only)
  void initRust({
    required bool enableEncryptionMemory,
    required bool autoCleanupMemory,
    required Duration cleanupIntervalMemory,
    bool showLog = false,
  }) {
    try {
      _showLog = showLog;
      _currentStorageType = StorageType.memory;

      if (_rustInitialized) {
        FastLog.d('⚠️ MemGuard Rust already initialized');
        return;
      }

      // Load Rust library
      _loadRustLibrary();

      if (_rustLib == null) {
        throw Exception('Failed to load Rust library');
      }

      // Initialize Rust with config
      final initFunc = _rustLib!.lookupFunction<Int32 Function(Pointer<Utf8>),
          int Function(Pointer<Utf8>)>('memguard_init_with_config');

      final config = {
        'enable_encryption': enableEncryptionMemory,
        'auto_cleanup': autoCleanupMemory,
        'cleanup_interval_ms': cleanupIntervalMemory.inMilliseconds,
        'platform': _getPlatform(),
      };

      final configJson = jsonEncode(config);

      if (_showLog) FastLog.d('🔧 MemGuard Rust Config: $configJson');

      final configPtr = configJson.toNativeUtf8();
      final result = initFunc(configPtr);
      calloc.free(configPtr);

      // Allow -1 (already initialized during hot restart)
      if (result != 0 && result != -1) {
        throw Exception('Rust initialization failed with code: $result');
      }

      _rustInitialized = true;

      if (_showLog) {
        FastLog.d('''
🛡️ MemGuard Rust Initialized
  Storage: Memory (Rust FFI)
  Encryption: ${enableEncryptionMemory ? '✅' : '❌'}
  Auto Cleanup: ${autoCleanupMemory ? '✅' : '❌'}
  Cleanup Interval: ${cleanupIntervalMemory.inMinutes} minutes
''');
      }
    } catch (e, stackTrace) {
      if (_showLog) {
        FastLog.d('❌ MemGuard Rust initialization failed: $e');
        FastLog.d('Stack trace: $stackTrace');
      }
      rethrow;
    }
  }

  /// 🚀 Initialize Platform Channels (Persistent/Secure storage)
  void initPlatform({
    required StorageType storageType,
    bool enableEncryptionMemory = true,
    bool showLog = false,
  }) {
    try {
      _showLog = showLog;
      _currentStorageType = storageType;

      if (_showLog) {
        FastLog.d('''
🛡️ MemGuard Platform Channels Initialized
  Storage: ${_storageTypeToString(storageType)} (Platform Channels) 
  Encryption: ${enableEncryptionMemory ? '✅' : '❌'}
''');
      }
    } catch (e, stackTrace) {
      if (_showLog) {
        FastLog.d('❌ MemGuard Platform initialization failed: $e');
        FastLog.d('Stack trace: $stackTrace');
      }
      rethrow;
    }
  }

  /// 🔐 Store data
  Future<void> store(String key, String value) async {
    _checkInitialized();

    try {
      switch (_currentStorageType) {
        case StorageType.memory:
          await _storeRust(key, value);
          break;
        case StorageType.deviceSecure:
          await _storePlatform(key, value);
          break;
        case null:
          throw StateError('Storage type not set');
      }
    } catch (e, stackTrace) {
      if (_showLog) {
        FastLog.d('❌ Store failed for key $key: $e');
        FastLog.d('Stack trace: $stackTrace');
      }
      rethrow;
    }
  }

  /// 🔓 Retrieve data
  Future<String?> retrieve(String key) async {
    _checkInitialized();

    try {
      switch (_currentStorageType) {
        case StorageType.memory:
          return await _retrieveRust(key);
        case StorageType.deviceSecure:
          return await _retrievePlatform(key);
        case null:
          throw StateError('Storage type not set');
      }
    } catch (e, stackTrace) {
      if (_showLog) {
        FastLog.d('❌ Retrieve failed for key $key: $e');
        FastLog.d('Stack trace: $stackTrace');
      }
      return null;
    }
  }

  /// 🔄 Perform operation with zero-copy (Rust only)
  Future<R> performSecureOperation<R>(
    String key,
    R Function(Pointer<Uint8> data, int length) operation,
  ) async {
    if (_currentStorageType != StorageType.memory) {
      throw UnsupportedError(
          'Secure buffer operations only available for memory storage');
    }
    _checkRustInitialized();

    final getBufferFunc = _rustLib!.lookupFunction<
        Pointer<Uint8> Function(Pointer<Utf8>, Pointer<Int64>),
        Pointer<Uint8> Function(
            Pointer<Utf8>, Pointer<Int64>)>('memguard_get_buffer');

    final keyPtr = key.toNativeUtf8();
    final lengthPtr = calloc<Int64>();

    final dataPtr = getBufferFunc(keyPtr, lengthPtr);
    final length = lengthPtr.value;

    calloc.free(keyPtr);
    calloc.free(lengthPtr);

    if (dataPtr.address == 0) {
      throw Exception('Data not found for key: $key');
    }

    try {
      final result = operation(dataPtr, length);

      if (_showLog) {
        FastLog.d('⚡ Secure operation performed on key: $key');
      }

      return result;
    } finally {
      _zeroizeBuffer(dataPtr, length);
    }
  }

  /// 🗑️ Delete key
  Future<void> delete(String key) async {
    _checkInitialized();

    try {
      switch (_currentStorageType) {
        case StorageType.memory:
          await _deleteRust(key);
          break;
        case StorageType.deviceSecure:
          await _deletePlatform(key);
          break;
        case null:
          throw StateError('Storage type not set');
      }
    } catch (e, stackTrace) {
      if (_showLog) {
        FastLog.e('❌ Delete failed for key $key: $e');
        FastLog.e('Stack trace: $stackTrace');
      }
      rethrow;
    }
  }

  /// 🧹 Cleanup memory (Rust only)
  void cleanupMemory() {
    if (_currentStorageType != StorageType.memory || !_rustInitialized) return;

    try {
      final cleanupFunc = _rustLib!
          .lookupFunction<Void Function(), void Function()>(
              'memguard_cleanup_memory');

      cleanupFunc();

      if (_showLog) {
        FastLog.d('🧹 Memory cleanup performed');
      }
    } catch (e) {
      if (_showLog) {
        FastLog.e('⚠️ Memory cleanup failed: $e');
      }
    }
  }

  /// 🧹 Cleanup all storage
  void cleanupAll() {
    try {
      switch (_currentStorageType) {
        case StorageType.memory:
          if (_rustInitialized) {
            final cleanupAllFunc = _rustLib!
                .lookupFunction<Void Function(), void Function()>(
                    'memguard_cleanup_all');
            cleanupAllFunc();
          }
          break;
        case StorageType.deviceSecure:
          _cleanupPlatform();
          break;
        case null:
          break;
      }

      if (_showLog) {
        FastLog.d('🗑️ All storage cleaned up');
      }
    } catch (e) {
      if (_showLog) {
        FastLog.e('⚠️ Full cleanup failed: $e');
      }
    }
  }

  /// 🔍 Check if key exists
  Future<bool> contains(String key) async {
    _checkInitialized();

    try {
      switch (_currentStorageType) {
        case StorageType.memory:
          return await _containsRust(key);
        case StorageType.deviceSecure:
          return await _containsPlatform(key);
        case null:
          throw StateError('Storage type not set');
      }
    } catch (e) {
      if (_showLog) {
        FastLog.e('⚠️ Contains check failed for key $key: $e');
      }
      return false;
    }
  }

  /// 📊 Get storage statistics
  Future<Map<String, dynamic>> getStats() async {
    _checkInitialized();

    try {
      switch (_currentStorageType) {
        case StorageType.memory:
          return await _getStatsRust();
        case StorageType.deviceSecure:
          return await _getStatsPlatform();
        case null:
          throw StateError('Storage type not set');
      }
    } catch (e) {
      if (_showLog) {
        FastLog.e('⚠️ Failed to get stats: $e');
      }
      return {};
    }
  }

  // =============== RUST METHODS ===============
  Future<void> _storeRust(String key, String value) async {
    final storeFunc = _rustLib!.lookupFunction<
        Int32 Function(Pointer<Utf8>, Pointer<Utf8>),
        int Function(Pointer<Utf8>, Pointer<Utf8>)>('memguard_store');

    final keyPtr = key.toNativeUtf8();
    final valuePtr = value.toNativeUtf8();

    final result = storeFunc(keyPtr, valuePtr);

    calloc.free(keyPtr);
    calloc.free(valuePtr);

    if (result != 0) {
      throw Exception('Store operation failed with code: $result');
    }

    if (_showLog) {
      FastLog.d('💾 [Rust] Stored key: $key');
    }
  }

  Future<String?> _retrieveRust(String key) async {
    final retrieveFunc = _rustLib!.lookupFunction<
        Pointer<Utf8> Function(Pointer<Utf8>),
        Pointer<Utf8> Function(Pointer<Utf8>)>('memguard_retrieve');

    final keyPtr = key.toNativeUtf8();
    final valuePtr = retrieveFunc(keyPtr);
    calloc.free(keyPtr);

    if (valuePtr.address == 0) {
      if (_showLog) FastLog.w('🔍 [Rust] Key not found: $key');
      return null;
    }

    final value = valuePtr.toDartString();
    _freeRustString(valuePtr);

    if (_showLog) {
      FastLog.d('📖 [Rust] Retrieved key: $key');
    }

    return value;
  }

  Future<void> _deleteRust(String key) async {
    final deleteFunc = _rustLib!.lookupFunction<Int32 Function(Pointer<Utf8>),
        int Function(Pointer<Utf8>)>('memguard_delete');

    final keyPtr = key.toNativeUtf8();
    final result = deleteFunc(keyPtr);
    calloc.free(keyPtr);

    if (result != 0) {
      throw Exception('Delete operation failed with code: $result');
    }

    if (_showLog) {
      FastLog.d('🗑️ [Rust] Deleted key: $key');
    }
  }

  Future<bool> _containsRust(String key) async {
    final containsFunc = _rustLib!.lookupFunction<Int32 Function(Pointer<Utf8>),
        int Function(Pointer<Utf8>)>('memguard_contains');

    final keyPtr = key.toNativeUtf8();
    final result = containsFunc(keyPtr);
    calloc.free(keyPtr);

    final exists = result == 1;

    if (_showLog) {
      FastLog.d('🔍 [Rust] Contains key $key: $exists');
    }

    return exists;
  }

  Future<Map<String, dynamic>> _getStatsRust() async {
    final statsFunc = _rustLib!
        .lookupFunction<Pointer<Utf8> Function(), Pointer<Utf8> Function()>(
            'memguard_get_stats');

    final statsPtr = statsFunc();

    if (statsPtr.address == 0) {
      return {};
    }

    final statsJson = statsPtr.toDartString();
    _freeRustString(statsPtr);

    final stats = jsonDecode(statsJson);

    if (_showLog) {
      FastLog.d('📊 [Rust] Statistics: $stats');
    }

    return Map<String, dynamic>.from(stats);
  }

  // =============== PLATFORM METHODS ===============
  Future<String?> _retrievePlatform(String key) async {
    try {
      // First try to load from Rust (in-memory cache)
      final memoryData = await _retrieveRust(key);
      if (memoryData != null) {
        if (_showLog) FastLog.i('🔍 Loaded data from Rust cache: $key');
        return memoryData;
      }

      // If not in Rust cache, try platform storage (Secure Enclave/Keychain)
      final result = await _platformChannel.invokeMethod('retrieve', {
        'storageType': _storageTypeToString(_currentStorageType!),
        'key': key,
      });

      if (result != true) {
        if (_showLog) FastLog.w('⚠️ Key not found in platform storage: $key');
        return null;
      }

      return await _retrieveRust(key);
    } on PlatformException catch (e) {
      if (_showLog) {
        FastLog.e('❌ [Platform] Retrieve failed for key $key: ${e.message}');
      }
      return null;
    } catch (e) {
      if (_showLog) {
        FastLog.e('❌ [Platform] Unexpected error for key $key: $e');
      }
      return null;
    }
  }

  Future<void> _storePlatform(String key, String value) async {
    try {
      final result = await _platformChannel.invokeMethod('store', {
        'storageType': _storageTypeToString(_currentStorageType!),
        'key': key,
        'value': value,
      });

      if (result != true) {
        if (_showLog) FastLog.e('⚠️ Error Stored key : $key');
      }

      if (_showLog) {
        FastLog.d('💾 [Platform] Stored key: $key');
      }
    } on PlatformException catch (e) {
      throw Exception('Platform store failed: ${e.message}');
    } catch (e) {
      throw Exception('Platform store unexpected error: $e');
    }
  }

  Future<void> _deletePlatform(String key) async {
    try {
      final result = await _platformChannel.invokeMethod('delete', {
        'storageType': _storageTypeToString(_currentStorageType!),
        'key': key,
      });

      if (result != true) {
        if (_showLog) FastLog.e('⚠️ Error Deleted key : $key');
      }

      if (_showLog) {
        FastLog.d('🗑️ [Platform] Deleted key: $key');
      }
    } on PlatformException catch (e) {
      throw Exception('Platform delete failed: ${e.message}');
    }
  }

  Future<bool> _containsPlatform(String key) async {
    try {
      final result = await _platformChannel.invokeMethod('contains', {
        'storageType': _storageTypeToString(_currentStorageType!),
        'key': key,
      });

      if (result != true) {
        if (_showLog) FastLog.e('⚠️ Error Check Contain key : $key');
      }

      if (_showLog) {
        final exists = result == 1;
        FastLog.d('🔍 [Platform] Contains key $key: $exists');
      }

      return true;
    } on PlatformException {
      return false;
    }
  }

  Future<Map<String, dynamic>> _getStatsPlatform() async {
    try {
      final result = await _platformChannel.invokeMethod('getStats', {
        'storageType': _storageTypeToString(_currentStorageType!),
      });

      final String statsKey =
          "db3b1c9812e7edc529fa4dbd05c3f793db5743dbefdb5b4be1f2f0c0bb0d9ec1"; // Unique hash for "memguard_stats"

      if (result != true) {
        if (showLog) {
          FastLog.e('⚠️ Error Get Stats : $statsKey');
        }
      }

      final String? dataStats = await _retrieveRust(statsKey);

      if (dataStats == null || dataStats.isEmpty) {
        return {};
      }

      // Decode JSON string
      final decoded = jsonDecode(dataStats);

      // Ensure it's a Map
      if (decoded is Map<String, dynamic>) {
        return decoded;
      } else {
        FastLog.e('⚠️ Stats is not a JSON map: $dataStats');
        return {};
      }
    } on PlatformException catch (e) {
      FastLog.e('⚠️ Platform error: $e');
      return {};
    } catch (e) {
      FastLog.e('⚠️ Decode error: $e');
      return {};
    }
  }

  void _cleanupPlatform() {
    try {
      _platformChannel.invokeMethod('cleanupAll', {
        'storageType': _storageTypeToString(_currentStorageType!),
      });
    } on PlatformException {
      // Ignore cleanup errors
    }
  }

  // =============== UTILITY METHODS ===============
  void _loadRustLibrary() {
    try {
      if (defaultTargetPlatform == TargetPlatform.android) {
        _rustLib = DynamicLibrary.open('libmemguard_ffi.so');
      } else {
        throw Exception('Platform not supported: $defaultTargetPlatform');
      }

      if (_rustLib == null) {
        throw Exception('Failed to load Rust dynamic library');
      }

      if (_showLog) {
        FastLog.i('📚 Rust library loaded successfully');
      }
    } catch (e, stackTrace) {
      if (_showLog) {
        FastLog.e('❌ Failed to load Rust library: $e');
        FastLog.e('Stack trace: $stackTrace');
      }
      rethrow;
    }
  }

  void _freeRustString(Pointer<Utf8> ptr) {
    try {
      final freeFunc = _rustLib!.lookupFunction<Void Function(Pointer<Utf8>),
          void Function(Pointer<Utf8>)>('memguard_free_string');
      freeFunc(ptr);
    } catch (_) {
      // Function might not exist, ignore
    }
  }

  void _zeroizeBuffer(Pointer<Uint8> ptr, int length) {
    try {
      final zeroizeFunc = _rustLib!.lookupFunction<
          Void Function(Pointer<Uint8>, Int64),
          void Function(Pointer<Uint8>, int)>('memguard_zeroize_buffer');
      zeroizeFunc(ptr, length);
    } catch (_) {
      // Manual zeroization as fallback
      for (var i = 0; i < length; i++) {
        ptr[i] = 0;
      }
    }
  }

  void _checkInitialized() {
    if (_currentStorageType == null) {
      throw StateError(
          'MemGuard is not initialized. Call initRust() or initPlatform() first.');
    }
  }

  void _checkRustInitialized() {
    if (!_rustInitialized) {
      throw StateError('Rust storage not initialized. Call initRust() first.');
    }
  }

  String _storageTypeToString(StorageType type) {
    switch (type) {
      case StorageType.memory:
        return 'memory';
      case StorageType.deviceSecure:
        return 'device_secure';
    }
  }

  String _getPlatform() {
    if (defaultTargetPlatform == TargetPlatform.android) return 'android';
    if (defaultTargetPlatform == TargetPlatform.iOS) return 'ios';
    if (defaultTargetPlatform == TargetPlatform.linux) return 'linux';
    if (defaultTargetPlatform == TargetPlatform.macOS) return 'macos';
    if (defaultTargetPlatform == TargetPlatform.windows) return 'windows';
    return 'unknown';
  }

  /// 🔧 Get current storage type
  StorageType? get currentStorageType => _currentStorageType;

  /// 🔧 Check if Rust is initialized
  bool get isRustInitialized => _rustInitialized;

  /// 🔧 Get debug mode status
  bool get showLog => _showLog;
}

/// 📦 Static Access Helper (Storage Type Aware)
class MemGuardStatic {
  /// 🔐 Store data (auto-selects based on storage type)
  static Future<void> store(String key, String value,
      {StorageType? storageType}) async {
    final core = MemGuardCore.instance;

    // If storage type specified, validate it matches current config
    if (storageType != null && storageType != core.currentStorageType) {
      throw ArgumentError('Requested storage type ($storageType) '
          'does not match initialized type (${core.currentStorageType})');
    }

    await core.store(key, value);
  }

  /// 🔓 Retrieve data (auto-selects based on storage type)
  static Future<String?> retrieve(String key,
      {StorageType? storageType}) async {
    final core = MemGuardCore.instance;

    // If storage type specified, validate it matches current config
    if (storageType != null && storageType != core.currentStorageType) {
      throw ArgumentError('Requested storage type ($storageType) '
          'does not match initialized type (${core.currentStorageType})');
    }

    return await core.retrieve(key);
  }

  /// 🔄 Perform secure operation (Rust memory only)
  static Future<R> performSecureOperation<R>(
    String key,
    R Function(Pointer<Uint8> data, int length) operation,
  ) async {
    final core = MemGuardCore.instance;

    if (core.currentStorageType != StorageType.memory) {
      throw UnsupportedError(
          'Secure buffer operations only available for memory storage');
    }

    return await core.performSecureOperation(key, operation);
  }

  /// 🗑️ Delete key (auto-selects based on storage type)
  static Future<void> delete(String key, {StorageType? storageType}) async {
    final core = MemGuardCore.instance;

    // If storage type specified, validate it matches current config
    if (storageType != null && storageType != core.currentStorageType) {
      throw ArgumentError('Requested storage type ($storageType) '
          'does not match initialized type (${core.currentStorageType})');
    }

    await core.delete(key);
  }

  /// 📊 Get statistics (auto-selects based on storage type)
  static Future<Map<String, dynamic>> getStats(
      {StorageType? storageType}) async {
    final core = MemGuardCore.instance;

    // If storage type specified, validate it matches current config
    if (storageType != null && storageType != core.currentStorageType) {
      throw ArgumentError('Requested storage type ($storageType) '
          'does not match initialized type (${core.currentStorageType})');
    }

    return await core.getStats();
  }

  /// 🔍 Check if key exists (auto-selects based on storage type)
  static Future<bool> contains(String key, {StorageType? storageType}) async {
    final core = MemGuardCore.instance;

    // If storage type specified, validate it matches current config
    if (storageType != null && storageType != core.currentStorageType) {
      throw ArgumentError('Requested storage type ($storageType) '
          'does not match initialized type (${core.currentStorageType})');
    }

    return await core.contains(key);
  }

  /// 🧹 Cleanup memory (Rust only)
  static void cleanupMemory() {
    MemGuardCore.instance.cleanupMemory();
  }

  /// 🧹 Cleanup all storage
  static void cleanupAll() {
    MemGuardCore.instance.cleanupAll();
  }

  /// 🚀 Initialize Memory Storage (Rust FFI)
  static void initMemoryStorage({
    required bool enableEncryptionMemory,
    required bool autoCleanupMemory,
    required Duration cleanupIntervalMemory,
    bool showLog = false,
  }) {
    MemGuardCore.instance.initRust(
      enableEncryptionMemory: enableEncryptionMemory,
      autoCleanupMemory: autoCleanupMemory,
      cleanupIntervalMemory: cleanupIntervalMemory,
      showLog: showLog,
    );
  }

  /// 🚀 Initialize Platform Storage
  static void initPlatformStorage({
    required StorageType storageType,
    bool enableEncryptionMemory = true,
    bool showLog = false,
  }) {
    if (storageType == StorageType.memory) {
      throw ArgumentError('Use initMemoryStorage() for memory storage');
    }

    MemGuardCore.instance.initPlatform(
      storageType: storageType,
      enableEncryptionMemory: enableEncryptionMemory,
      showLog: showLog,
    );
  }

  /// 🔧 Get current storage type
  static StorageType? get currentStorageType =>
      MemGuardCore.instance.currentStorageType;

  /// 🔧 Check if initialized
  static bool get isInitialized =>
      MemGuardCore.instance.currentStorageType != null;
}

/// 🎯 Extension for BuildContext
extension MemGuardExtension on BuildContext {
  MemGuardCore get memguard => MemGuardCore.instance;
}

/// 🎯 Extension for String operations
extension MemGuardStringExtension on String {
  /// 🔐 Store this string with the given key
  Future<void> storeAs(String key, {StorageType? storageType}) async {
    await MemGuardStatic.store(key, this, storageType: storageType);
  }
}

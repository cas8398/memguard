import 'package:flutter_test/flutter_test.dart';
import 'package:memguard/memguard.dart';
import 'dart:io';

void main() {
  // Skip tests on non-Android platforms or when library is missing
  bool shouldRunTests() {
    // Only run tests on Android
    if (!Platform.isAndroid) {
      print('⚠️  Skipping tests: Not running on Android');
      return false;
    }

    // Check if .so files exist
    final jniLibsDir = Directory('android/app/src/main/jniLibs');
    if (!jniLibsDir.existsSync()) {
      print('⚠️  Skipping tests: jniLibs directory not found');
      return false;
    }

    // Check for at least one .so file
    final soFiles = jniLibsDir
        .listSync(recursive: true)
        .where((file) => file.path.endsWith('.so'))
        .toList();

    if (soFiles.isEmpty) {
      print('⚠️  Skipping tests: No .so files found in jniLibs');
      return false;
    }

    print('✅ Found ${soFiles.length} .so files, proceeding with tests');
    return true;
  }

  group('MemGuard Tests', () {
    setUpAll(() {
      // Skip all tests if conditions aren't met
      if (!shouldRunTests()) {
        return;
      }
    });

    test('MemGuard initialization', () {
      if (!shouldRunTests()) {
        return; // Skip test
      }

      expect(
        () => MemGuardCore.instance.initRust(
          enableEncryptionMemory: true,
          autoCleanupMemory: true,
          cleanupIntervalMemory: const Duration(seconds: 1),
        ),
        returnsNormally,
        reason: 'Should initialize without throwing',
      );
    });

    test('Store and retrieve value', () async {
      if (!shouldRunTests()) {
        return; // Skip test
      }

      // Initialize first
      MemGuardCore.instance.initRust(
        enableEncryptionMemory: true,
        autoCleanupMemory: true,
        cleanupIntervalMemory: const Duration(seconds: 1),
      );

      // Store
      await MemGuardStatic.store('test_key', 'test_value');

      // Retrieve
      final value = await MemGuardStatic.retrieve('test_key');
      expect(value, equals('test_value'));
    });

    test('Delete value', () async {
      if (!shouldRunTests()) {
        return; // Skip test
      }

      // Initialize first
      MemGuardCore.instance.initRust(
        enableEncryptionMemory: true,
        autoCleanupMemory: true,
        cleanupIntervalMemory: const Duration(seconds: 1),
      );

      // Store
      await MemGuardStatic.store('delete_test', 'to_be_deleted');

      // Delete
      await MemGuardStatic.delete('delete_test');

      // Verify deleted
      final deletedValue = await MemGuardStatic.retrieve('delete_test');
      expect(deletedValue, isNull);
    });

    test('Get stats', () async {
      if (!shouldRunTests()) {
        return; // Skip test
      }

      // Initialize first
      MemGuardCore.instance.initRust(
        enableEncryptionMemory: true,
        autoCleanupMemory: true,
        cleanupIntervalMemory: const Duration(seconds: 1),
      );

      // Store something to generate stats
      await MemGuardStatic.store('stats_key', 'stats_value');

      // Get stats
      final stats = await MemGuardStatic.getStats();

      // Stats should be a map
      expect(stats, isA<Map<String, dynamic>>());

      // Should contain at least some keys
      expect(stats.keys, isNotEmpty);
    });
  });
}

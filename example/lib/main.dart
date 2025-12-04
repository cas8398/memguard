import 'package:flutter/material.dart';
import 'package:flutter/widgets.dart';
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

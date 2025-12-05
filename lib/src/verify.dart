import 'dart:io';
import 'package:crypto/crypto.dart';

Future<void> verifySha256_linux(File file) async {
  const String expectedSha256 =
      '6bc98fec88f596dbcc07306a3520d04292507827093e48a6e2c759d820c226ea';

  final bytes = await file.readAsBytes();
  final actual = sha256.convert(bytes).toString();

  if (actual != expectedSha256.toLowerCase()) {
    throw Exception(
      'SHA256 mismatch!\n'
      'Expected: $expectedSha256\n'
      'Actual:   $actual',
    );
  }
}

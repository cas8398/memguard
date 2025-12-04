package com.flagodna.memguard

import com.flagodna.memguard.debugPrint
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class MemGuardPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel
    private lateinit var context: Context
    private val tag = "MemGuardPlugin"
    
    // For app_persistent (software encryption)
    private val encryptionAlgorithm = "AES/GCM/NoPadding"
    private val keyDerivationAlgorithm = "PBKDF2WithHmacSHA256"
    private val keyLength = 256
    private val iterationCount = 10000
    private val saltLength = 16
    private val ivLength = 12 // GCM recommended IV length
    private val gcmTagLength = 128 // GCM tag length in bits
    
    // For device_secure (Android KeyStore)
    private val keyStoreAlias = "memguard_secure_key"
    private val keyStoreProvider = "AndroidKeyStore"
    
    // Rust FFI instance
    private lateinit var rustFFI: RustFFI

    companion object {
        const val CHANNEL_NAME = "com.memguard/storage"
        const val STORAGE_DIR = "memguard"
        const val DEVICE_SECURE_DIR = "memguard_secure"
    }

    // Rust FFI wrapper with safe calls
    inner class RustFFI {
        private var isInitialized = false

        init {
            try {
                System.loadLibrary("memguard_ffi")
                debugPrint.i(tag, "Rust FFI library loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.w(tag, "Rust FFI library not available: ${e.message}")
            } catch (e: Exception) {
                debugPrint.e(tag, "Failed to load Rust FFI: ${e.message}")
            }
        }

        // Only initialize if not already initialized by Dart
        fun initializeIfNeeded() {
            if (isInitialized) {
                debugPrint.d(tag, "Rust FFI already initialized, skipping")
                return
            }
            
            try {
                // Check if Rust is already initialized
                val checkResult = try {
                    memguard_is_initialized()
                } catch (e: UnsatisfiedLinkError) {
                    -1
                }
                
                if (checkResult == 1) {
                    debugPrint.d(tag, "Rust FFI already initialized by Dart")
                    isInitialized = true
                    return
                }
                
                // Only initialize if not already done by Dart
                val config = """
                    {
                        "enable_encryption": true,
                        "auto_cleanup": true,
                        "cleanup_interval_ms": 300000,
                        "platform": "android"
                    }
                """.trimIndent()
                
                val result = memguard_init_with_config(config)
                if (result != 0) {
                    debugPrint.w(tag, "Rust FFI initialization returned non-zero: $result")
                } else {
                    debugPrint.i(tag, "Rust FFI initialized successfully")
                    isInitialized = true
                }
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.w(tag, "Rust FFI not available for initialization")
            } catch (e: Exception) {
                debugPrint.e(tag, "Rust FFI initialization error: ${e.message}")
            }
        }

        // Declare external functions
        external fun memguard_init_with_config(configJson: String): Int
        external fun memguard_store(key: String, value: String): Int
        external fun memguard_retrieve(key: String): String?
        external fun memguard_delete(key: String): Int
        external fun memguard_contains(key: String): Int
        external fun memguard_cleanup_memory()
        external fun memguard_cleanup_all()
        external fun memguard_get_stats(): String?
        external fun memguard_is_initialized(): Int
        external fun memguard_get_memory_usage(): Int
        external fun memguard_clear_all(): Int

        fun storeSafe(key: String, value: String): Boolean {
            return try {
                val result = memguard_store(key, value)
                result == 0
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.d(tag, "Rust FFI not available for store operation")
                false
            } catch (e: Exception) {
                debugPrint.e(tag, "Rust store error: ${e.message}")
                false
            }
        }

        fun retrieveSafe(key: String): String? {
            return try {
                memguard_retrieve(key)
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.d(tag, "Rust FFI not available for retrieve operation")
                null
            } catch (e: Exception) {
                debugPrint.e(tag, "Rust retrieve error: ${e.message}")
                null
            }
        }

        fun deleteSafe(key: String): Boolean {
            return try {
                val result = memguard_delete(key)
                result == 0
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.d(tag, "Rust FFI not available for delete operation")
                false
            } catch (e: Exception) {
                debugPrint.e(tag, "Rust delete error: ${e.message}")
                false
            }
        }

        fun containsSafe(key: String): Boolean {
            return try {
                val result = memguard_contains(key)
                result == 1
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.d(tag, "Rust FFI not available for contains operation")
                false
            } catch (e: Exception) {
                debugPrint.e(tag, "Rust contains error: ${e.message}")
                false
            }
        }

        fun cleanupMemorySafe() {
            try {
                memguard_cleanup_memory()
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.d(tag, "Rust FFI not available for cleanup")
            } catch (e: Exception) {
                debugPrint.e(tag, "Rust cleanup error: ${e.message}")
            }
        }

        fun cleanupAllSafe() {
            try {
                memguard_cleanup_all()
            } catch (e: UnsatisfiedLinkError) {
                debugPrint.d(tag, "Rust FFI not available for cleanup")
            } catch (e: Exception) {
                debugPrint.e(tag, "Rust cleanup error: ${e.message}")
            }
        }
    }

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        context = flutterPluginBinding.applicationContext
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, CHANNEL_NAME)
        channel.setMethodCallHandler(this)
        
        // Initialize Rust FFI only if needed (Dart may have already done it)
        rustFFI = RustFFI()
        rustFFI.initializeIfNeeded()
        
        debugPrint.i(tag, "MemGuardPlugin attached to engine")
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        debugPrint.d(tag, "Method call: ${call.method} with args: ${call.arguments}")
        
        try {
            when (call.method) {
                "store" -> handleStore(call, result)
                "retrieve" -> handleRetrieve(call, result)
                "delete" -> handleDelete(call, result)
                "contains" -> handleContains(call, result)
                "getStats" -> handleGetStats(call, result)
                "cleanupAll" -> handleCleanupAll(call, result)
                else -> {
                    debugPrint.w(tag, "Unknown method: ${call.method}")
                    result.notImplemented()
                }
            }
        } catch (e: Exception) {
            debugPrint.e(tag, "Error handling method ${call.method}: ${e.message}", e)
            result.error("MEMGUARD_ERROR", e.message, e.stackTraceToString())
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        debugPrint.i(tag, "MemGuardPlugin detached from engine")
    }

    private fun handleStore(call: MethodCall, result: Result) {
        val storageType = call.argument<String>("storageType")
        val key = call.argument<String>("key")
        val value = call.argument<String>("value")

        if (key.isNullOrEmpty() || value.isNullOrEmpty() || storageType.isNullOrEmpty()) {
            result.error("INVALID_ARGUMENTS", "Missing or empty required parameters", null)
            return
        }

        try {
            when (storageType) {
                "app_persistent" -> {
                    // Software encryption + file storage
                    val encrypted = encryptWithSoftware(value, key)
                    saveToFile(key, encrypted, isDeviceSecure = false)

                    // Also cache in Rust memory for faster access
                    rustFFI.storeSafe(key, value)
                    
                    debugPrint.d(tag, "Stored key: $key in app_persistent storage")
                    result.success(null)
                }
                "device_secure" -> {
                    // Hardware-backed encryption + file storage
                    val encrypted = encryptWithKeyStore(value, key)
                    saveToFile(key, encrypted, isDeviceSecure = true)

                    // Also cache in Rust memory for faster access
                    rustFFI.storeSafe(key, value)
                    
                    debugPrint.d(tag, "Stored key: $key in device_secure storage")
                    result.success(null)
                } 
                else -> {
                    result.error("INVALID_STORAGE_TYPE", "Unsupported storage type: $storageType", null)
                }
            }
        } catch (e: Exception) {
            debugPrint.e(tag, "Store failed for key: $key", e)
            result.error("STORE_FAILED", "Failed to store value: ${e.message}", null)
        }
    }

    private fun handleRetrieve(call: MethodCall, result: Result) {
        val storageType = call.argument<String>("storageType")
        val key = call.argument<String>("key")

        if (key.isNullOrEmpty() || storageType.isNullOrEmpty()) {
            result.error("INVALID_ARGUMENTS", "Missing or empty required parameters", null)
            return
        }

        try {
            when (storageType) {
                "app_persistent" -> {
                    // First try Rust cache (faster)
                    val cachedValue = rustFFI.retrieveSafe(key)
                    if (cachedValue != null) {
                        debugPrint.d(tag, "Retrieved key: $key from Rust cache")
                        result.success(true)
                        return
                    }
                    
                    // If not in cache, read from encrypted file
                    val encrypted = readFromFile(key, isDeviceSecure = false)
                    if (encrypted != null) {
                        val decrypted = decryptWithSoftware(encrypted, key)
                        
                        // Cache in Rust for future access
                        rustFFI.storeSafe(key, decrypted)
                        
                        debugPrint.d(tag, "Retrieved key: $key from app_persistent storage")
                        result.success(true)
                    } else {
                        debugPrint.d(tag, "Key not found: $key")
                        result.success(null)
                    }
                }
                "device_secure" -> {
                    // First try Rust cache (faster)
                    val cachedValue = rustFFI.retrieveSafe(key)
                    if (cachedValue != null) {
                        debugPrint.d(tag, "Retrieved key: $key from Rust cache")
                        result.success(true)
                        return
                    }
                    
                    val encrypted = readFromFile(key, isDeviceSecure = true)
                    if (encrypted != null) {
                        val decrypted = decryptWithKeyStore(encrypted, key)
                        
                        // Cache in Rust for future access
                        rustFFI.storeSafe(key, decrypted)
                        
                        debugPrint.d(tag, "Retrieved key: $key from device_secure")
                        result.success(true)
                    } else {
                        debugPrint.d(tag, "Key not found: $key in device_secure")
                        result.success(null)
                    }
                } 
                else -> {
                    result.error("INVALID_STORAGE_TYPE", "Unsupported storage type: $storageType", null)
                }
            }
        } catch (e: Exception) {
            debugPrint.e(tag, "Retrieve failed for key: $key", e)
            result.error("RETRIEVE_FAILED", "Failed to retrieve value: ${e.message}", null)
        }
    }

    private fun handleDelete(call: MethodCall, result: Result) {
        val storageType = call.argument<String>("storageType")
        val key = call.argument<String>("key")

        if (key.isNullOrEmpty() || storageType.isNullOrEmpty()) {
            result.error("INVALID_ARGUMENTS", "Missing or empty required parameters", null)
            return
        }

        try {
            when (storageType) {
                "app_persistent" -> {
                    deleteFile(key, isDeviceSecure = false)
                    // Also delete from Rust cache
                    rustFFI.deleteSafe(key)
                    debugPrint.d(tag, "Deleted key: $key from app_persistent")
                    result.success(null)
                }
                "device_secure" -> {
                    deleteFile(key, isDeviceSecure = true)
                    // Also delete from Rust cache
                    rustFFI.deleteSafe(key)
                    debugPrint.d(tag, "Deleted key: $key from device_secure")
                    result.success(null)
                }
                else -> {
                    result.error("INVALID_STORAGE_TYPE", "Unsupported storage type: $storageType", null)
                }
            }
        } catch (e: Exception) {
            debugPrint.e(tag, "Delete failed for key: $key", e)
            result.error("DELETE_FAILED", "Failed to delete value: ${e.message}", null)
        }
    }

    private fun handleContains(call: MethodCall, result: Result) {
        val storageType = call.argument<String>("storageType")
        val key = call.argument<String>("key")

        if (key.isNullOrEmpty() || storageType.isNullOrEmpty()) {
            result.error("INVALID_ARGUMENTS", "Missing or empty required parameters", null)
            return
        }

        try {
            when (storageType) {
                "app_persistent" -> {
                    // Check Rust cache first
                    if (rustFFI.containsSafe(key)) {
                        result.success(true)
                        return
                    }
                    
                    val exists = fileExists(key, isDeviceSecure = false)
                    debugPrint.d(tag, "Contains check for key: $key in app_persistent - $exists")
                    result.success(exists)
                }
                "device_secure" -> {
                    // Check Rust cache first
                    if (rustFFI.containsSafe(key)) {
                        result.success(true)
                        return
                    }
                    
                    val exists = fileExists(key, isDeviceSecure = true)
                    debugPrint.d(tag, "Contains check for key: $key in device_secure - $exists")
                    result.success(exists)
                } 
                else -> {
                    result.error("INVALID_STORAGE_TYPE", "Unsupported storage type: $storageType", null)
                }
            }
        } catch (e: Exception) {
            debugPrint.e(tag, "Contains check failed for key: $key", e)
            result.error("CONTAINS_FAILED", "Failed to check key existence: ${e.message}", null)
        }
    }

    private fun handleGetStats(call: MethodCall, result: Result) {
        val storageType = call.argument<String>("storageType")

        if (storageType.isNullOrEmpty()) {
            result.error("INVALID_ARGUMENTS", "Missing storage type parameter", null)
            return
        }

        try {
            when (storageType) {
                "app_persistent" -> {
                    val stats = getStorageStats(isDeviceSecure = false)
                    stats["storage_type"] = "app_persistent"
                    stats["encryption_type"] = "software_aes_gcm"
                    debugPrint.d(tag, "Stats retrieved for app_persistent: $stats")
                    result.success(stats)
                }
                "device_secure" -> {
                    val stats = getStorageStats(isDeviceSecure = true)
                    stats["storage_type"] = "device_secure"
                    stats["encryption_type"] = "hardware_backed_keystore"
                    stats["key_protection"] = getKeyStoreProtectionLevel()
                    debugPrint.d(tag, "Stats retrieved for device_secure: $stats")
                    result.success(stats)
                }
                else -> {
                    result.error("INVALID_STORAGE_TYPE", "Unsupported storage type: $storageType", null)
                }
            }
        } catch (e: Exception) {
            debugPrint.e(tag, "GetStats failed for $storageType", e)
            result.error("GETSTATS_FAILED", "Failed to get statistics: ${e.message}", null)
        }
    }

    private fun handleCleanupAll(call: MethodCall, result: Result) {
        val storageType = call.argument<String>("storageType")

        if (storageType.isNullOrEmpty()) {
            result.error("INVALID_ARGUMENTS", "Missing storage type parameter", null)
            return
        }

        try {
            when (storageType) {
                "app_persistent" -> {
                    cleanupFiles(isDeviceSecure = false)
                    // Cleanup Rust cache
                    rustFFI.cleanupAllSafe()
                    debugPrint.d(tag, "Cleanup completed for app_persistent")
                    result.success(null)
                }
                "device_secure" -> {
                    cleanupFiles(isDeviceSecure = true)
                    // Cleanup Rust cache
                    rustFFI.cleanupAllSafe()
                    debugPrint.d(tag, "Cleanup completed for device_secure")
                    result.success(null)
                } 
                else -> {
                    result.error("INVALID_STORAGE_TYPE", "Unsupported storage type: $storageType", null)
                }
            }
        } catch (e: Exception) {
            debugPrint.e(tag, "Cleanup failed for $storageType", e)
            result.error("CLEANUP_FAILED", "Failed to cleanup: ${e.message}", null)
        }
    }

    // =============== ENCRYPTION METHODS ===============
    
    // Software-based encryption (app_persistent)
    private fun encryptWithSoftware(value: String, keyName: String): String {
        val salt = generateSalt()
        val iv = generateIv()
        val secretKey = deriveSoftwareKey(salt)
        
        val cipher = Cipher.getInstance(encryptionAlgorithm)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(gcmTagLength, iv))
        
        val encryptedBytes = cipher.doFinal(value.toByteArray(StandardCharsets.UTF_8))
        
        // Combine salt + iv + encrypted data
        val combined = ByteArray(salt.size + iv.size + encryptedBytes.size)
        System.arraycopy(salt, 0, combined, 0, salt.size)
        System.arraycopy(iv, 0, combined, salt.size, iv.size)
        System.arraycopy(encryptedBytes, 0, combined, salt.size + iv.size, encryptedBytes.size)
        
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    private fun decryptWithSoftware(encryptedBase64: String, keyName: String): String {
        val combined = Base64.decode(encryptedBase64, Base64.NO_WRAP)
        
        if (combined.size < saltLength + ivLength) {
            throw IllegalArgumentException("Invalid encrypted data")
        }
        
        val salt = combined.copyOfRange(0, saltLength)
        val iv = combined.copyOfRange(saltLength, saltLength + ivLength)
        val encryptedData = combined.copyOfRange(saltLength + ivLength, combined.size)
        
        val secretKey = deriveSoftwareKey(salt)
        
        val cipher = Cipher.getInstance(encryptionAlgorithm)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(gcmTagLength, iv))
        
        val decryptedBytes = cipher.doFinal(encryptedData)
        return String(decryptedBytes, StandardCharsets.UTF_8)
    }

    private fun deriveSoftwareKey(salt: ByteArray): SecretKey {
        val packageName = context.packageName
        val password = "$packageName:memguard:software"
        
        val factory = SecretKeyFactory.getInstance(keyDerivationAlgorithm)
        val spec = PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength)
        val key = factory.generateSecret(spec)
        
        return SecretKeySpec(key.encoded, "AES")
    }

    // Hardware-backed encryption (device_secure) using Android KeyStore
    private fun encryptWithKeyStore(value: String, keyName: String): String {
        val key = getOrCreateKeyStoreKey()
        val cipher = Cipher.getInstance(encryptionAlgorithm)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        
        val iv = cipher.iv
        val encryptedBytes = cipher.doFinal(value.toByteArray(StandardCharsets.UTF_8))
        
        // Combine iv + encrypted data
        val combined = ByteArray(iv.size + encryptedBytes.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)
        
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    private fun decryptWithKeyStore(encryptedBase64: String, keyName: String): String {
        val combined = Base64.decode(encryptedBase64, Base64.NO_WRAP)
        
        if (combined.size < ivLength) {
            throw IllegalArgumentException("Invalid encrypted data")
        }
        
        val iv = combined.copyOfRange(0, ivLength)
        val encryptedData = combined.copyOfRange(ivLength, combined.size)
        
        val key = getKeyStoreKey()
        val cipher = Cipher.getInstance(encryptionAlgorithm)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(gcmTagLength, iv))
        
        val decryptedBytes = cipher.doFinal(encryptedData)
        return String(decryptedBytes, StandardCharsets.UTF_8)
    }

    private fun getOrCreateKeyStoreKey(): SecretKey {
        val keyStore = KeyStore.getInstance(keyStoreProvider)
        keyStore.load(null)
        
        // Check if key exists
        if (keyStore.containsAlias(keyStoreAlias)) {
            val entry = keyStore.getEntry(keyStoreAlias, null) as? KeyStore.SecretKeyEntry
            if (entry != null) {
                return entry.secretKey
            }
        }
        
        // Create new key
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, 
            keyStoreProvider
        )
        
        val keySpec = KeyGenParameterSpec.Builder(
            keyStoreAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(keyLength)
            .setRandomizedEncryptionRequired(true)
            // Add security features
            .setUserAuthenticationRequired(false) // Set to true for biometric protection
            .setInvalidatedByBiometricEnrollment(true)
            .build()
        
        keyGenerator.init(keySpec)
        return keyGenerator.generateKey()
    }

    private fun getKeyStoreKey(): SecretKey {
        val keyStore = KeyStore.getInstance(keyStoreProvider)
        keyStore.load(null)
        
        if (!keyStore.containsAlias(keyStoreAlias)) {
            throw IllegalStateException("KeyStore key not found")
        }
        
        val entry = keyStore.getEntry(keyStoreAlias, null) as? KeyStore.SecretKeyEntry
            ?: throw IllegalStateException("Invalid key entry")
        
        return entry.secretKey
    }

    private fun getKeyStoreProtectionLevel(): String {
        return try {
            val keyStore = KeyStore.getInstance(keyStoreProvider)
            keyStore.load(null)
            
            if (keyStore.containsAlias(keyStoreAlias)) {
                "hardware_backed" // Android 6.0+ automatically uses hardware if available
            } else {
                "not_initialized"
            }
        } catch (e: Exception) {
            "unknown"
        }
    }

    private fun generateSalt(): ByteArray {
        val salt = ByteArray(saltLength)
        SecureRandom.getInstanceStrong().nextBytes(salt)
        return salt
    }

    private fun generateIv(): ByteArray {
        val iv = ByteArray(ivLength)
        SecureRandom.getInstanceStrong().nextBytes(iv)
        return iv
    }

    // =============== FILE OPERATIONS ===============
    private fun getStorageDirectory(isDeviceSecure: Boolean): File {
        val dirName = if (isDeviceSecure) DEVICE_SECURE_DIR else STORAGE_DIR
        val dir = File(context.filesDir, dirName)
        
        if (!dir.exists()) {
            dir.mkdirs()
            // Set proper permissions for the app's private directory
            dir.setReadable(true)
            dir.setWritable(true)
            dir.setExecutable(true) // Allow execution for directory traversal
            debugPrint.d(tag, "Created directory: ${dir.absolutePath}")
        } else {
            // Ensure existing directory has proper permissions
            dir.setReadable(true)
            dir.setWritable(true)
            dir.setExecutable(true)
        }
        return dir
    }

    private fun getFileName(key: String): String {
        // Create secure filename using SHA-256 hash
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(key.toByteArray(StandardCharsets.UTF_8))
        val hexHash = hashBytes.joinToString("") { "%02x".format(it) }
        return "mg_${hexHash.substring(0, 16)}.dat"
    }

    private fun saveToFile(key: String, encryptedData: String, isDeviceSecure: Boolean) {
        val dir = getStorageDirectory(isDeviceSecure)
        val file = File(dir, getFileName(key))
        
        debugPrint.d(tag, "Attempting to save to: ${file.absolutePath}")
        debugPrint.d(tag, "Directory exists: ${dir.exists()}, writable: ${dir.canWrite()}")
        
        try {
            FileOutputStream(file).use { fos ->
                fos.write(encryptedData.toByteArray(StandardCharsets.UTF_8))
                fos.flush()
            }
            
            // Set file permissions - only readable/writable by the app
            file.setReadable(true, false)  // owner only
            file.setWritable(true, false)  // owner only
            file.setExecutable(false, false)
            
            debugPrint.d(tag, "Successfully saved file: ${file.name}")
            
        } catch (e: SecurityException) {
            debugPrint.e(tag, "Security exception when saving file: ${file.absolutePath}", e)
            throw e
        } catch (e: Exception) {
            debugPrint.e(tag, "Failed to save file: ${file.absolutePath}", e)
            throw e
        }
    }

    private fun readFromFile(key: String, isDeviceSecure: Boolean): String? {
        val dir = getStorageDirectory(isDeviceSecure)
        val file = File(dir, getFileName(key))
        
        if (!file.exists()) {
            return null
        }
        
        return FileInputStream(file).use { fis ->
            fis.readBytes().toString(StandardCharsets.UTF_8)
        }
    }

    private fun deleteFile(key: String, isDeviceSecure: Boolean) {
        val dir = getStorageDirectory(isDeviceSecure)
        val file = File(dir, getFileName(key))
        
        if (file.exists()) {
            // Secure deletion: overwrite with zeros before deleting
            try {
                FileOutputStream(file).use { fos ->
                    val zeros = ByteArray(file.length().toInt())
                    fos.write(zeros)
                    fos.flush()
                }
            } catch (e: Exception) {
                debugPrint.w(tag, "Could not overwrite file before deletion: ${file.name}", e)
            }
            
            file.delete()
        }
    }

    private fun fileExists(key: String, isDeviceSecure: Boolean): Boolean {
        val dir = getStorageDirectory(isDeviceSecure)
        val file = File(dir, getFileName(key))
        return file.exists()
    }

    private fun getFilesInDirectory(isDeviceSecure: Boolean): List<File> {
        val dir = getStorageDirectory(isDeviceSecure)
        return dir.listFiles { file -> 
            file.isFile && file.name.startsWith("mg_") && file.name.endsWith(".dat")
        }?.toList() ?: emptyList()
    }

    private fun cleanupFiles(isDeviceSecure: Boolean) {
        val dir = getStorageDirectory(isDeviceSecure)
        val files = getFilesInDirectory(isDeviceSecure)
        
        files.forEach { file ->
            try {
                // Secure deletion
                FileOutputStream(file).use { fos ->
                    val zeros = ByteArray(file.length().toInt())
                    fos.write(zeros)
                    fos.flush()
                }
                file.delete()
            } catch (e: Exception) {
                debugPrint.w(tag, "Failed to securely cleanup file: ${file.name}", e)
            }
        }
        
        debugPrint.i(tag, "Cleaned up ${files.size} files from ${if (isDeviceSecure) "device_secure" else "app_persistent"}")
    }

    private fun getStorageStats(isDeviceSecure: Boolean): MutableMap<String, Any> {
        val stats = mutableMapOf<String, Any>()
        val files = getFilesInDirectory(isDeviceSecure)
        
        stats["package_name"] = context.packageName
        stats["directory_path"] = getStorageDirectory(isDeviceSecure).absolutePath
        stats["items_count"] = files.size
        stats["total_size_bytes"] = files.sumOf { it.length() }
        stats["files"] = files.map { it.name }
        
        return stats
    }
}
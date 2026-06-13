package com.rafaeldiascampos.securecommunication

import android.util.Base64
import okhttp3.Interceptor
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import java.nio.Buffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class EncryptedRequestInterceptor: Interceptor {
    private val encryptedMediaType: MediaType = "application/octet-stream".toMediaType()
    private val jsonMediaType: MediaType = "application/json; charset=utf-8".toMediaType()
    private val password: String = "secret-password-123"

    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()

        val originalResponse: Response =
            if (originalRequest.body != null) {
                try {
                    val buffer = okio.Buffer()
                    originalRequest.body!!.writeTo(buffer)

                    val encryptedBody =
                        encrypt(buffer.readUtf8(), password)

                    val body = encryptedBody.toRequestBody(encryptedMediaType)

                    val request = originalRequest.newBuilder()
                        .method(originalRequest.method, body)
                        .build()

                    chain.proceed(request)
                } catch (e: Exception) {
                    e.printStackTrace()
                    // Fall back to sending the original request
                    chain.proceed(originalRequest)
                }
            } else {
                chain.proceed(originalRequest)
            }

        if (originalResponse.body != null) {
            return try {
                val decryptedBody =
                    decrypt(originalResponse.body!!.string(), password)

                val body = decryptedBody.toResponseBody(jsonMediaType)

                originalResponse.newBuilder()
                    .body(body)
                    .build()
            } catch (e: Exception) {
                e.printStackTrace()
                // Return the original response if decryption fails
                originalResponse
            }
        }

        return originalResponse
    }

    private fun deriveKey(password: String, salt: ByteArray): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(password.toCharArray(), salt, 100000, 256)
        val key = factory.generateSecret(spec).encoded
        return SecretKeySpec(key, "AES")
    }

    private fun encrypt(text: String, password: String): String {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)

        val key = deriveKey(password, salt)

        // Use a 12-byte IV for GCM
        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            key,
            GCMParameterSpec(128, iv) // 128-bit authentication tag
        )

        // ciphertext || authTag
        val encryptedData = cipher.doFinal(text.toByteArray(Charsets.UTF_8))

        // Store IV || ciphertext || authTag
        val combined = ByteArray(iv.size + encryptedData.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(encryptedData, 0, combined, iv.size, encryptedData.size)

        val saltBase64 = Base64.encodeToString(salt, Base64.NO_WRAP)
        val combinedBase64 = Base64.encodeToString(combined, Base64.NO_WRAP)

        return "$combinedBase64:$saltBase64"
    }

    private fun decrypt(encryptedBase64: String, password: String): String {
        val parts = encryptedBase64.split(":")
        require(parts.size == 2) { "Invalid encrypted data format" }

        val combined = Base64.decode(parts[0], Base64.NO_WRAP)
        val salt = Base64.decode(parts[1], Base64.NO_WRAP)

        // First 12 bytes are the IV
        val iv = combined.copyOfRange(0, 12)

        // Remaining bytes are ciphertext || authTag
        val encryptedData = combined.copyOfRange(12, combined.size)

        val key = deriveKey(password, salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            GCMParameterSpec(128, iv)
        )

        val decryptedData = cipher.doFinal(encryptedData)

        return decryptedData.toString(Charsets.UTF_8)
    }
}
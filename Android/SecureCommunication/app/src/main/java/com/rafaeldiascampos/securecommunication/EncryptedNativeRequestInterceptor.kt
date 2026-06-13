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

class EncryptedNativeRequestInterceptor: Interceptor {
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

    external fun encrypt(text: String, password: String): String
    external fun decrypt(encryptedBase64: String, password: String): String

    companion object {
        init {
            System.loadLibrary("securecommunication")
        }
    }
}
package com.rafaeldiascampos.securecommunication

import android.content.Context
import okhttp3.Interceptor
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import java.nio.charset.StandardCharsets

class EncryptedAsymmetricRequestInterceptor(
    context: Context
) : Interceptor {

    private val encryptedMediaType: MediaType =
        "application/octet-stream".toMediaType()

    private val jsonMediaType: MediaType =
        "application/json; charset=utf-8".toMediaType()

    private val clientPrivateKey: String =
        context.assets.open("client-private.pem").use {
            String(it.readBytes(), StandardCharsets.UTF_8)
        }

    private val serverPublicKey: String =
        context.assets.open("server-public.pem").use {
            String(it.readBytes(), StandardCharsets.UTF_8)
        }

    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()

        val originalResponse: Response =
            if (originalRequest.body != null) {
                try {
                    val buffer = okio.Buffer()
                    originalRequest.body!!.writeTo(buffer)

                    val encryptedBody =
                        encryptAsymmetric(buffer.readUtf8(), serverPublicKey)

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
                    decryptAsymmetric(originalResponse.body!!.string(), clientPrivateKey)

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

    external fun encryptAsymmetric(
        text: String,
        publicKey: String
    ): String

    external fun decryptAsymmetric(
        encryptedBase64: String,
        privateKey: String
    ): String

    companion object {
        init {
            System.loadLibrary("securecommunication")
        }
    }
}
package com.rafaeldiascampos.securecommunication

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import android.os.Handler
import android.content.Context
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Interceptor
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException

class RequestHandler(private val handler: Handler) {
    private val jsonMediaType: MediaType = "application/json; charset=utf-8".toMediaType()

    private fun doRequest(uri: String, interceptor: Interceptor?) {
        handler.sendMessage(
            handler.obtainMessage(0, "Trying to send a request to $uri")
        )

        // Create the client
        val clientBuilder = OkHttpClient.Builder()
        interceptor?.let {
            clientBuilder.addInterceptor(it)
        }

        val client: OkHttpClient = clientBuilder.build()

        // Create request body
        val bodyJson: JsonObject = buildJsonObject {
            put("uri", uri)
            put("data", "This is the request data")
        }
        val body: RequestBody = bodyJson.toString().toRequestBody(jsonMediaType)

        // Create request object
        val request: Request = okhttp3.Request.Builder()
            .url(uri)
            .post(body)
            .build()

        // Send request
        client.newCall(request)
            .enqueue(object : Callback {
                override fun onFailure(call: Call, e: IOException) {
                    handler.sendMessage(
                        handler.obtainMessage(
                            0,
                            "Exception when making request: ${e.message}"
                        )
                    )
                }

                override fun onResponse(call: Call, response: Response) {
                    response.use {
                        if (!response.isSuccessful) {
                            handler.sendMessage(
                                handler.obtainMessage(0, "Received response with invalid status code: ${response.code}")
                            )
                            return
                        }

                        val res = try {
                            response.body?.string()
                        } catch (e: Exception) {
                            e.printStackTrace()
                            null
                        }
                        res?.let { responseJsonString ->
                            val responseJson : JsonElement
                            try {
                                responseJson = Json.parseToJsonElement(responseJsonString)
                            }
                            catch (e: SerializationException) {
                                handler.sendMessage(
                                    handler.obtainMessage(0, "Received response is not a valid Json: $res")
                                )
                                return
                            }

                            val jsonCode: Int = responseJson.jsonObject["code"]?.jsonPrimitive?.intOrNull ?: -1

                            if (jsonCode != 200) {
                                handler.sendMessage(
                                    handler.obtainMessage(0, "Received response has invalid code: $res")
                                )
                                return
                            }

                            handler.sendMessage(
                                handler.obtainMessage(0, "Received response OK: $res")
                            )

                        } ?: run {
                            handler.sendMessage(
                                handler.obtainMessage(0, "Received invalid response")
                            )
                        }
                    }
                }
            })
    }

    fun unencryptedRequest(host: String) {
        val uri: String = "$host/unencrypted"
        doRequest(uri, null)
    }

    fun encryptedRequest(host: String) {
        val uri: String = "$host/encrypted"
        doRequest(uri, EncryptedRequestInterceptor())
    }

    fun encryptedNativeRequest(host: String) {
        val uri: String = "$host/encryptedNative"
        doRequest(uri, EncryptedNativeRequestInterceptor())
    }

    fun encryptedAsymmetricRequest(host: String, context: Context) {
        val uri: String = "$host/encryptedAsymmetric"
        doRequest(uri, EncryptedAsymmetricRequestInterceptor(context))
    }
}
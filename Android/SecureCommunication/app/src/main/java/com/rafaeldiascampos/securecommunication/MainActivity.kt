package com.rafaeldiascampos.securecommunication

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Message
import android.util.Log
import com.rafaeldiascampos.securecommunication.databinding.ActivityMainBinding
import androidx.core.content.edit

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var requestHandler: RequestHandler

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        loadHost()

        // Create a handler to receive log results
        val handler = object : Handler(Looper.getMainLooper()) {
            override fun handleMessage(msg: Message) {
                val responseData = msg.obj as String
                var logText = "${binding.logTextBox.text.toString()}\n"
                logText += responseData
                binding.logTextBox.setText(logText)
            }
        }

        // Create Request Handler
        requestHandler = RequestHandler(handler)

        // Set on click listeners to buttons
        binding.requestUnencryptedButton.setOnClickListener {
            binding.logTextBox.setText("")

            val host = getHost()
            requestHandler.unencryptedRequest(host)
        }

        binding.requestEncryptedButton.setOnClickListener {
            binding.logTextBox.setText("")

            val host = getHost()
            requestHandler.encryptedRequest(host)
        }

        binding.requestEncryptedNativeButton.setOnClickListener {
            binding.logTextBox.setText("")

            val host = getHost()
            requestHandler.encryptedNativeRequest(host)
        }

        binding.requestEncryptedAsymmetricalButton.setOnClickListener {
            binding.logTextBox.setText("")

            val host = getHost()
            requestHandler.encryptedAsymmetricRequest(host, applicationContext)
        }
    }

    private fun getHost(): String {
        val host = binding.hostTextbox.text.toString()
        saveHost(host)
        return host
    }

    private fun saveHost(host: String) {
        getSharedPreferences("app_prefs", MODE_PRIVATE)
            .edit {
                putString("host", host)
            }
    }

    private fun loadHost() {
        val host = getSharedPreferences("app_prefs", MODE_PRIVATE)
            .getString("host", null)

        host?.let {
            binding.hostTextbox.setText(it)
        }
    }

}
# SecureCommunication

SecureCommunication is a challenge project consisting of an Android application and a backend server that communicate using both **symmetric** and **asymmetric cryptography**.

The goal of this repository is to provide a target for **mobile application security researchers** and **penetration testers** who want to practice developing **Frida scripts** and other dynamic instrumentation techniques to intercept, analyze, and manipulate encrypted network traffic.

## Repository Structure

```
SecureCommunication/
├── Android/    # Android client application
└── Backend/    # Backend server implementation
```

* **Android/** – Contains the Android application responsible for establishing secure communication with the backend.
* **Backend/** – Contains the server-side implementation that exchanges encrypted messages with the Android client.

## Features

The Android application supports 4 different types of communication with the backend, offering different levels of challenge.

* Unencrypted request: Sends a normal HTTP/S request to the server. Useful to verify if the traffic interception is working.
* Encrypted request: Sends an HTTP/S request with the payload encrypted using AES256-GCM with a static key. The received payload from the server is also encrypted using the same schema and key. The code that handles the encryption/decryption process is implemented in Java for easier reverse engineering.
* Encrypted native request: Uses the same cryptographic scheme as the previous request, however the code that handles the encryption/decryption process is implemented in a native library to offer a greater challenge.
* Encrypted Asymmetric request: The payload is encrypted using AES256-GCM with a randomly generated key, that is then encrypted using the server's public RSA key. The server encrypts the response's payload using the app's public RSA key. This code is also implemented in a native library to offer a greater challenge.

## Intended Use Cases

This project can be used to practice:

* Mobile application reverse engineering
* Dynamic analysis using Frida
* Hooking Java and native methods
* Bypassing client-side protections
* Understanding cryptographic workflows in Android applications
* Security training and Capture-the-Flag (CTF) style exercises

## Getting Started

### Android Application

If you simply want to use the application, you can download the latest pre-built APK from the repository's Actions page. Open the most recent successful workflow run, navigate to the Artifacts section, and download the app-debug artifact.

Alternatively, you can build the application yourself by opening the project in Android Studio and installing it on a compatible Android device or emulator. The project is configured to support both arm64 and x86 architectures, making it compatible with most physical devices and Android emulators.

### Backend Server

The backend implementation is located in the `Backend/` directory and is written in Node.js.

Before starting the server, install the required dependencies:

```bash
cd Backend
npm install
```

Once the installation is complete, start the server with:

```bash
node server.js
```

The server will then be ready to accept connections from the Android application.

## Script suggestions

The goal of this challenge is to intercept the plaintext communication using a proxy application, such as Burp Suite.

Some possible approaches include:

1. **Develop a Frida script that prints plaintext payloads to the console.**

   * Hook the application's encryption and decryption routines to capture data immediately before encryption and immediately after decryption.
   * This approach is relatively straightforward and is useful for understanding the application's traffic and cryptographic flow.
   * However, because the plaintext is only displayed in the console, it is less practical for interactive testing and does not easily allow the pentester to inspect or modify requests and responses before they are transmitted.

2. **Develop a Burp Suite extension that transparently decrypts and re-encrypts traffic.**

   * Use Frida or another instrumentation technique to recover the necessary cryptographic material (such as symmetric keys), then implement the application's encryption scheme within a Burp extension.
   * The extension can decrypt intercepted payloads for display in Burp, allow the user to modify them, and automatically re-encrypt them before forwarding the request to the application or the server.
   * This approach provides a much more convenient workflow for traffic analysis and manipulation, but it requires reverse engineering the encryption scheme and obtaining the keys used by the application.
   * In general, this technique is only practical for the symmetric encryption challenges. The asymmetric challenge uses ephemeral session keys exchanged via public-key cryptography, making transparent decryption and re-encryption significantly more complex.
   
3. **Develop a Frida script to disable the application's encryption and decryption routines, combined with a Burp Suite extension to perform those operations externally.**

   * Instead of merely observing the plaintext, hook the application's cryptographic functions so that they return the input unchanged (or just base64 encoded).
   * A companion Burp Suite extension can then transparently encrypt outgoing requests and decrypt incoming responses, allowing Burp to operate entirely on plaintext while the server continues to receive correctly formatted encrypted messages.
   * This approach provides a seamless interception experience and enables full modification of requests and responses directly within Burp.
   * Successfully implementing this solution requires understanding the application's cryptographic workflow and reproducing it accurately in the Burp extension. It is generally most applicable to the symmetric encryption challenges, where the necessary keys and algorithms can be extracted and reused.

4. **Develop a Frida script that exposes the application's encryption and decryption routines via RPC, and a Burp Suite extension that delegates cryptographic operations to the device.**

   * Rather than reimplementing the cryptographic algorithms in Burp, use Frida's RPC mechanism to export functions that invoke the application's own encryption and decryption code.
   * A Python bridge script can communicate with the injected Frida agent and expose a simple socket-based interface. The Burp Suite extension then sends plaintext or ciphertext to the Python process, which forwards the data to the application for processing and returns the result.
   * This architecture allows Burp to transparently display and modify plaintext traffic while relying on the application's original implementation for all cryptographic operations.
   * Although this solution is more complex and requires coordinating multiple components (Frida, Python, and Burp), it has a major advantage: it does **not** require reverse engineering or reimplementing the encryption scheme. As a result, it can be applied to both symmetric and asymmetric encryption challenges, as well as custom or proprietary cryptographic implementations, provided the relevant functions can be hooked and invoked on the device.

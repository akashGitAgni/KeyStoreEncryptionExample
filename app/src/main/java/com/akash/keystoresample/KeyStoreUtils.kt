package com.akash.keystoresample

interface KeyStoreUtils {

    fun getOrCreateEncryptionKey(): ByteArray
}
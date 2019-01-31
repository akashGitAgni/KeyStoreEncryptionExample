package com.akash.keystoresample

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import timber.log.Timber

object SharedPrefUtils {
    private const val PREF_NAME = "realm_key"
    private const val KEY = "iv_and_encrypted_key"

    fun save(context: Context, ivAndEncryptedKey: ByteArray) {

        val encodedData = encode(ivAndEncryptedKey)

        Timber.d("Key encoded %s", encodedData)

        getPreference(context).edit()
                .putString(KEY, encode(ivAndEncryptedKey))
                .apply()
    }

    fun load(context: Context): ByteArray? {
        val pref = getPreference(context)

        val ivAndEncryptedKey = pref.getString(KEY, null) ?: return null

        Timber.d("Key  in SP%s", ivAndEncryptedKey)

        return decode(ivAndEncryptedKey)
    }

    private fun encode(data: ByteArray?): String? {
        return if (data == null) {
            null
        } else Base64.encodeToString(data, Base64.DEFAULT)
    }

    private fun decode(encodedData: String?): ByteArray? {
        return if (encodedData == null) {
            null
        } else Base64.decode(encodedData, Base64.DEFAULT)
    }

    private fun getPreference(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
    }
}
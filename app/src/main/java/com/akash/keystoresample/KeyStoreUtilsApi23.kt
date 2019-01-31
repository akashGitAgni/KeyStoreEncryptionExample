package org.vumc.mycap.core

import android.app.Application
import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.akash.keystoresample.KeyStoreUtils
import com.akash.keystoresample.SharedPrefUtils
import io.realm.RealmConfiguration
import timber.log.Timber
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.*
import java.security.cert.CertificateException
import java.util.*
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec

@RequiresApi(Build.VERSION_CODES.M)
class KeyStoreUtilsApi23(private val context: Application) : KeyStoreUtils {
    companion object {
        private const val KEYSTORE_PROVIDER_NAME = "AndroidKeyStore"
        private const val KEY_ALIAS = "mycap_realm_key"

        private const val TRANSFORMATION = (KeyProperties.KEY_ALGORITHM_AES
                + "/" + KeyProperties.BLOCK_MODE_CBC
                + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7)
        private const val AUTH_VALID_DURATION_IN_SECOND = 30

        private val ORDER_FOR_ENCRYPTED_DATA = ByteOrder.BIG_ENDIAN
    }

    private val rng = SecureRandom()
    private val keyStore = prepareKeyStore()


    override fun getOrCreateEncryptionKey(): ByteArray {
        val key = SharedPrefUtils.load(context)

        Timber.d("Got Key %s", key)
        val content = if (key != null) {
            decryptKeyForRealm(key)
        } else {
            if (!containsEncryptionKey()) {
                generateKeyInKeystore()
            }

            val newKey = generateKeyForRealm()
            encryptAndSaveKeyForRealm(newKey)
            newKey
        }

        return Arrays.copyOfRange(content, 0, 64);
    }

    private val keyguardManager: KeyguardManager
        get() = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

    private fun containsEncryptionKey(): Boolean {
        try {
            return keyStore.containsAlias(KEY_ALIAS)
        } catch (e: KeyStoreException) {
            throw RuntimeException(e)
        }

    }

    private fun generateKeyForRealm(): ByteArray {
        val keyForRealm = ByteArray(RealmConfiguration.KEY_LENGTH)
        rng.nextBytes(keyForRealm)
        return keyForRealm
    }

    private fun generateKeyInKeystore() {
        val keyGenerator: KeyGenerator
        try {
            keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                KEYSTORE_PROVIDER_NAME
            )
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: NoSuchProviderException) {
            throw RuntimeException(e)
        }

        val keySpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            .setUserAuthenticationValidityDurationSeconds(
                AUTH_VALID_DURATION_IN_SECOND
            )
            .build()
        try {
            keyGenerator.init(keySpec)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException(e)
        }

        keyGenerator.generateKey()

    }

    private fun encryptAndSaveKeyForRealm(keyForRealm: ByteArray): ByteArray {
        val ks = prepareKeyStore()
        val cipher = prepareCipher()

        val iv: ByteArray
        val encryptedKeyForRealm: ByteArray
        try {
            val key = ks.getKey(KEY_ALIAS, null) as SecretKey
            cipher.init(Cipher.ENCRYPT_MODE, key)

            encryptedKeyForRealm = cipher.doFinal(keyForRealm)
            iv = cipher.iv
        } catch (e: InvalidKeyException) {
            throw RuntimeException("key for encryption is invalid", e)
        } catch (e: UnrecoverableKeyException) {
            throw RuntimeException("key for encryption is invalid", e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("key for encryption is invalid", e)
        } catch (e: KeyStoreException) {
            throw RuntimeException("key for encryption is invalid", e)
        } catch (e: BadPaddingException) {
            throw RuntimeException("key for encryption is invalid", e)
        } catch (e: IllegalBlockSizeException) {
            throw RuntimeException("key for encryption is invalid", e)
        }

        val ivAndEncryptedKey = ByteArray(Integer.SIZE + iv.size + encryptedKeyForRealm.size)

        val buffer = ByteBuffer.wrap(ivAndEncryptedKey)
        buffer.order(ORDER_FOR_ENCRYPTED_DATA)
        buffer.putInt(iv.size)
        buffer.put(iv)
        buffer.put(encryptedKeyForRealm)

        SharedPrefUtils.save(context, ivAndEncryptedKey)

        return ivAndEncryptedKey
    }

    private fun decryptKeyForRealm(ivAndEncryptedKey: ByteArray): ByteArray {
        val cipher = prepareCipher()
        val keyStore = prepareKeyStore()

        val buffer = ByteBuffer.wrap(ivAndEncryptedKey)
        buffer.order(ORDER_FOR_ENCRYPTED_DATA)

        val ivLength = buffer.int
        val iv = ByteArray(ivLength)
        val encryptedKey = ByteArray(ivAndEncryptedKey.size - Integer.SIZE - ivLength)

        buffer.get(iv)
        buffer.get(encryptedKey)

        try {
            val key = keyStore.getKey(KEY_ALIAS, null) as SecretKey
            val ivSpec = IvParameterSpec(iv)
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)

            return cipher.doFinal(encryptedKey)
        } catch (e: InvalidKeyException) {
            throw RuntimeException("key is invalid.")
        } catch (e: UnrecoverableKeyException) {
            throw RuntimeException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: BadPaddingException) {
            throw RuntimeException(e)
        } catch (e: KeyStoreException) {
            throw RuntimeException(e)
        } catch (e: IllegalBlockSizeException) {
            throw RuntimeException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException(e)
        }

    }

    private fun prepareKeyStore(): KeyStore {
        try {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER_NAME)
            ks.load(null)
            return ks
        } catch (e: KeyStoreException) {
            throw RuntimeException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: CertificateException) {
            throw RuntimeException(e)
        } catch (e: IOException) {
            throw RuntimeException(e)
        }

    }

    private fun prepareCipher(): Cipher {
        val cipher: Cipher
        try {
            cipher = Cipher.getInstance(TRANSFORMATION)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: NoSuchPaddingException) {
            throw RuntimeException(e)
        }

        return cipher
    }
}
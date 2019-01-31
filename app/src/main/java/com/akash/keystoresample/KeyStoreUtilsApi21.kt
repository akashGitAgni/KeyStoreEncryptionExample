@file:Suppress("DEPRECATION")

package org.vumc.mycap.core

import android.app.Application
import android.os.Build
import android.security.KeyPairGeneratorSpec
import androidx.annotation.RequiresApi
import com.akash.keystoresample.KeyStoreUtils
import com.akash.keystoresample.SharedPrefUtils
import io.realm.RealmConfiguration
import timber.log.Timber
import java.io.IOException
import java.math.BigInteger
import java.security.*
import java.security.cert.CertificateException
import java.util.*
import javax.crypto.Cipher
import javax.security.auth.x500.X500Principal

@RequiresApi(Build.VERSION_CODES.LOLLIPOP)
class KeyStoreUtilsApi21(private val context: Application) : KeyStoreUtils {

    companion object {
        private const val KEYSTORE_PROVIDER_NAME = "AndroidKeyStore"
        private const val KEY_ALIAS = "mycap_realm_key"
    }

    private val rng = SecureRandom()
    private val keyStore = prepareKeyStore()

    override fun getOrCreateEncryptionKey(): ByteArray {
        val key = SharedPrefUtils.load(context)

        Timber.d("Got Key %s", key)
        val content = if (key != null) {
            decryptString(key)
        } else {
            if (!containsEncryptionKey()) {
                generateKeyInKeystoreBefore23()
            }

            val newKey = generateKeyForRealm()
            SharedPrefUtils.save(context, encryptString(newKey))
            newKey
        }

        return Arrays.copyOfRange(content, 0, 64);
    }

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

    private fun generateKeyInKeystoreBefore23() {
        val keyGenerator: KeyPairGenerator
        try {
            keyGenerator = KeyPairGenerator
                .getInstance(
                    "RSA",
                    KEYSTORE_PROVIDER_NAME
                )

        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException(e)
        } catch (e: NoSuchProviderException) {
            throw RuntimeException(e)
        }
        val start = GregorianCalendar()
        val end = GregorianCalendar()
        end.add(Calendar.YEAR, 100)
        @Suppress("DEPRECATION") val keySpec = KeyPairGeneratorSpec.Builder(context)
            // You'll use the alias later to retrieve the key.  It's a key for the key!
            .setAlias(KEY_ALIAS)
            // The subject used for the self-signed certificate of the generated pair
            .setSubject(X500Principal("CN=$KEY_ALIAS"))
            // The serial number used for the self-signed certificate of the
            // generated pair.
            .setSerialNumber(BigInteger.valueOf(1337))
            // Date range of validity for the generated pair.
            .setStartDate(start.time)
            .setEndDate(end.time)
            .build();
        try {
            keyGenerator.initialize(keySpec)
        } catch (e: InvalidAlgorithmParameterException) {
            throw RuntimeException(e)
        }
        val keypair = keyGenerator.generateKeyPair()

    }

    private fun encryptString(value: ByteArray): ByteArray {
        var encodedBytes: ByteArray? = null
        val keyStore = prepareKeyStore()

        try {
            val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
            val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL")
            cipher.init(Cipher.ENCRYPT_MODE, entry.certificate.publicKey)
            encodedBytes = cipher.doFinal(value)
        } catch (e: Exception) {
            e.printStackTrace()
        }

        return encodedBytes!!
    }

    private fun decryptString(encryptedByted: ByteArray): ByteArray {
        var decodedBytes: ByteArray? = null

        val keyStore = prepareKeyStore()
        try {
            val entry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
            val c = Cipher.getInstance("RSA/ECB/PKCS1Padding", "AndroidOpenSSL")
            c.init(Cipher.DECRYPT_MODE, entry.privateKey)
            decodedBytes = c.doFinal(encryptedByted)
        } catch (e: Exception) {
            e.printStackTrace()
        }

        return decodedBytes!!
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
}
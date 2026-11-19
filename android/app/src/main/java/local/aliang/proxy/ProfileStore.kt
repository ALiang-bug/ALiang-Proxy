package local.aliang.proxy

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class SavedProfile(val yaml: String, val url: String = "", val selected: String = "", val choices: String = "{}", val resolver: String = "ali")

/** Both processes read an atomic encrypted envelope; no multiprocess preferences. */
class ProfileStore(context: Context) {
    private val file = AtomicFile(File(context.noBackupFilesDir, "profile.enc"))
    private val alias = "aliang.profile.v1"
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }
    fun save(profile: SavedProfile) {
        require(profile.yaml.toByteArray().size <= Limits.PROFILE_BYTES)
        val data = JSONObject().put("yaml", profile.yaml).put("url", profile.url)
            .put("selected", profile.selected).put("choices", profile.choices).put("resolver", profile.resolver).toString().toByteArray()
        require(data.size <= Limits.ENVELOPE_BYTES)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        val encrypted = cipher.doFinal(data)
        val stream = file.startWrite()
        try {
            stream.write(byteArrayOf(1, cipher.iv.size.toByte()))
            stream.write(cipher.iv); stream.write(encrypted)
            file.finishWrite(stream)
        } catch (e: Exception) { file.failWrite(stream); throw e }
        finally { data.fill(0) }
    }
    fun load(): SavedProfile? {
        if (!file.baseFile.exists()) return null
        val data = file.openRead().use { Limits.read(it, Limits.ENVELOPE_BYTES + 64) }
        require(data.size >= 30 && data[0] == 1.toByte() && data[1] == 12.toByte())
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, data.copyOfRange(2, 14)))
        }
        val plain = cipher.doFinal(data, 14, data.size - 14)
        try {
            val json = JSONObject(String(plain, Charsets.UTF_8))
            return SavedProfile(json.getString("yaml"), json.optString("url"), json.optString("selected"), json.optString("choices", "{}"), json.optString("resolver", "ali"))
        } finally { plain.fill(0) }
    }
    fun delete() = file.delete()
}

package com.ing.asia.licensecheck

import android.os.Bundle
import android.os.Environment
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import java.io.*
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec


class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val test = test()
        Log.d("Result", "$test")

//        test2()

    }


    fun getPublicKeyFromFile(fileLoc: String): PublicKey {
        var line: String? = ""
        val stringBuilder = StringBuilder()
        val inputStream: InputStream = FileInputStream(fileLoc)
        val reader = BufferedReader(InputStreamReader(inputStream))

        while (reader.readLine().also { line = it } != null) {
            if (line?.indexOf("-----BEGIN PUBLIC KEY-----") != -1) {
                while (reader.readLine().also { line = it } != null) {
                    if (line?.indexOf("-----END PUBLIC KEY-----") != -1) {
                        break
                    }
                    stringBuilder.append(line?.trim())
                }
                break
            }
        }
        if (line == null) {
            throw IOException("PUBLIC KEY" + " not found")
        }
        inputStream.close()

        val test = stringBuilder.toString();
        Log.d("publickey", test)
        val keyFactory: KeyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePublic(X509EncodedKeySpec(Base64.decode(test, Base64.DEFAULT)))
    }

    fun verifyLicense(): Boolean {
        val signature: Signature = Signature.getInstance("SHA256withRSA")

        val publicKeyFileLoc = "${Environment.getExternalStorageDirectory().absolutePath}/public-key.pem"
        val publicKey = test2()
        signature.initVerify(publicKey)

        val licenseFileLoc = "${Environment.getExternalStorageDirectory().absolutePath}/livenesslicense.bin"
        val sigfis = FileInputStream(licenseFileLoc)
        val sigToVerify = ByteArray(sigfis.available())
        sigfis.read(sigToVerify)
        sigfis.close()

        val datafis = this.resources.openRawResource(R.raw.asia_androidx_liveness)
        val bufin = BufferedInputStream(datafis)

        val buffer = ByteArray(1024)
        var len: Int
        while (bufin.available() !== 0) {
            len = bufin.read(buffer)
            signature.update(buffer, 0, len)
        }

        return signature.verify(sigToVerify)
    }

    fun getPublicKeyFromDer(filePath: String) : PublicKey{
        val fis = FileInputStream(filePath)
        val derInBytes = ByteArray(fis.available())
        fis.read(derInBytes)
        fis.close()

        val spec = X509EncodedKeySpec(derInBytes)
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePublic(spec)
    }
}
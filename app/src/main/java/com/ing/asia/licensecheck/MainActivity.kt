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

        var isValid = false

        try {

//            TOGGLE TESTING WITH PEM/DER FILE
            val publicKeyFileLoc =
                "${Environment.getExternalStorageDirectory().absolutePath}/public-key.pem"
//            val publicKeyFileLoc =
//                "${Environment.getExternalStorageDirectory().absolutePath}/public-key.der"

            val fis = FileInputStream(publicKeyFileLoc)
            if (publicKeyFileLoc.endsWith(".pem", true)) {
                isValid = verifyLicense(getPublicKeyFromPem(fis))
            } else if (publicKeyFileLoc.endsWith(".der", true)) {
                isValid = verifyLicense(getPublicKeyFromDer(fis))
            } else {
                Log.d("[ERROR]", "License file missing or invalid")
            }
        } catch (e: FileNotFoundException) {
            Log.d("[ERROR]", "License file missing or invalid")
        }

        Log.d("[Is Valid]", " $isValid")


    }

    fun getPublicKeyFromPem(fis: FileInputStream): PublicKey {
        var line: String? = ""
        val stringBuilder = StringBuilder()
        val reader = BufferedReader(InputStreamReader(fis))

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
        fis.close()

        val test = stringBuilder.toString();
        Log.d("publickey", test)
        val keyFactory: KeyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePublic(X509EncodedKeySpec(Base64.decode(test, Base64.DEFAULT)))
    }

    fun getPublicKeyFromDer(fis: FileInputStream): PublicKey {
        val derInBytes = ByteArray(fis.available())
        fis.read(derInBytes)
        fis.close()

        val spec = X509EncodedKeySpec(derInBytes)
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePublic(spec)
    }

    fun verifyLicense(publicKey: PublicKey): Boolean {
        val signature: Signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(publicKey)

        val licenseFileLoc =
            "${Environment.getExternalStorageDirectory().absolutePath}/livenesslicense.bin"
        val sigfis = FileInputStream(licenseFileLoc)
        val sigToVerify = ByteArray(sigfis.available())
        sigfis.read(sigToVerify)
        sigfis.close()

//        RECREATE DATA IN THE SIGNED LICENSE FILE GIVEN TO CUSTOMER. THIS IS THE DATA TO VERIFY AGAINST THE LICENSE
        val datafis = this.resources.openRawResource(R.raw.asia_androidx_liveness)
        val bufin = BufferedInputStream(datafis)

//        UPDATE THE SIGNATURE WITH THE DATA
        val buffer = ByteArray(1024)
        var len: Int
        while (bufin.available() != 0) {
            len = bufin.read(buffer)
            signature.update(buffer, 0, len)
        }

//        PERFORM VERIFICATION
        return signature.verify(sigToVerify)
    }

}
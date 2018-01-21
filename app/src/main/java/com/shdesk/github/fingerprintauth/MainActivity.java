package com.shdesk.github.fingerprintauth;


import android.app.KeyguardManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

    // key should be anything....
        String key = "YOUR-KEY";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);


        KeyguardManager manager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);

        FingerprintManager fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);

        // Check For Hardware.
            if(! fingerprintManager.isHardwareDetected())  {
                Toast.makeText(this, "Hardware Not Found", Toast.LENGTH_SHORT).show();
                return;
            }
        // Check For Fingerprint Is Saved.
            if(!manager.isKeyguardSecure()) {
                Toast.makeText(this, "KeyGuard Is Not Enable", Toast.LENGTH_SHORT).show();
                return;
            }


        // Create KeyStore To Store Save Encrypted Keys
            KeyStore keyStore = null;
            try {
                // Load Current AndroidKeyStore
                keyStore = KeyStore.getInstance("AndroidKeyStore");
            } catch (Exception ex) {
                Log.d("fingerprintAuth", "KeyStore |" + ex.getMessage());
            }

        // KeyGenerator Provide Functionality Of A Symmetric Key Generator.
            KeyGenerator generator = null;

            try {
                // AES Algorithm Is Used Because It Support All API LEVELS
                generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
            } catch (Exception ex) {
                Log.v("fingerprintAuth", "KeyGenerator | "+ ex.getMessage());
            }

        // Generate The Key
            try {
                keyStore.load(null);
                generator.init(
                        new KeyGenParameterSpec.Builder(
                                key,
                                KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                                // CBC - Cipher Block Chain
                                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)

                                // This Key Is Validate If User Validate It.
                                .setUserAuthenticationRequired(true)

                                // Set Padding Schemes | This is Optional
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)

                                // Generate The Key By All Params
                                .build()
                        /** We Can Also Add :
                         *     setCertificateNotAfter   |
                         *     setCertificateNotBefore  |- For Time Limitation
                         */
                );
                generator.generateKey();

            } catch (Exception ex) {
                Log.v("fingerprintAuth", "KeyGenerator - 2 | "+ ex.getMessage());
            }


        // Shows That Key Is Contains Using AES/CBC/Padding
            Cipher cipher = null;
            try {
                cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC+"/"+KeyProperties.ENCRYPTION_PADDING_PKCS7);
            } catch (Exception ex) {
                Log.v("fingerprintAuth", "Cipher | "+ ex.getMessage());
            }


        // Create Secret Key And Init The CipherMode Using Our SecretKey
            try {
                SecretKey secretKey = (SecretKey) keyStore.getKey(key, null);

                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            } catch (Exception ex) {
                Log.v("fingerprintAuth", "Cipher -2 | "+ ex.getMessage());
            }

        // Fingerprint Manager
        FingerprintManager.CryptoObject object = new FingerprintManager.CryptoObject(cipher);

        // This Object Is Used For Cancel Authentication
            CancellationSignal cancel = new CancellationSignal();

        // FLAG | Is Optional | So It Should Be 0 [ As Per Documentation ]
        fingerprintManager.authenticate(object, cancel, 0, new FingerprintManager.AuthenticationCallback() {

            // This Part Will Run When Max Limit Reach Fingerprint [ Too Many Attempt ]
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Toast.makeText(MainActivity.this, "AuthError :"+ errString, Toast.LENGTH_SHORT).show();
            }

            // Help When Finger AuthFound Some Issue [ Ex. Finger Moved etc. ]
                @Override
                public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                    super.onAuthenticationHelp(helpCode, helpString);
                    Toast.makeText(MainActivity.this, "AuthHelp"+helpString, Toast.LENGTH_SHORT).show();
                }

            // Fingerprint Got Matched. [ Success ]
                @Override
                public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    Toast.makeText(MainActivity.this, "Validation Done.", Toast.LENGTH_SHORT).show();
                }

            // Unreachable Error
                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    Toast.makeText(MainActivity.this, "AuthFail", Toast.LENGTH_SHORT).show();
                }
        }, null);

    }
}

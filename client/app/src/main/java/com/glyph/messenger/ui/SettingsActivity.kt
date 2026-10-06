package com.glyph.messenger.ui

import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.glyph.messenger.GlyphApp
import com.glyph.messenger.R

class SettingsActivity : AppCompatActivity() {

    private lateinit var app: GlyphApp
    private lateinit var btnSettingsBack: ImageButton
    private lateinit var txtSettingsUsername: TextView
    private lateinit var txtSettingsSignKey: TextView
    private lateinit var txtSettingsDhKey: TextView
    private lateinit var btnExportRecovery: Button
    private lateinit var editSettingsRelayUrl: EditText
    private lateinit var btnSaveRelayUrl: Button
    private lateinit var txtIdentitiesList: TextView
    private lateinit var btnAddIdentity: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        app = application as GlyphApp
        initViews()
        loadData()
    }

    private fun initViews() {
        btnSettingsBack = findViewById(R.id.btnSettingsBack)
        txtSettingsUsername = findViewById(R.id.txtSettingsUsername)
        txtSettingsSignKey = findViewById(R.id.txtSettingsSignKey)
        txtSettingsDhKey = findViewById(R.id.txtSettingsDhKey)
        btnExportRecovery = findViewById(R.id.btnExportRecovery)
        editSettingsRelayUrl = findViewById(R.id.editSettingsRelayUrl)
        btnSaveRelayUrl = findViewById(R.id.btnSaveRelayUrl)
        txtIdentitiesList = findViewById(R.id.txtIdentitiesList)
        btnAddIdentity = findViewById(R.id.btnAddIdentity)

        btnSettingsBack.setOnClickListener {
            finish()
        }

        btnSaveRelayUrl.setOnClickListener {
            val url = editSettingsRelayUrl.text.toString().trim()
            if (url.isNotEmpty()) {
                app.relayClient.relayBaseUrl = url
                Toast.makeText(this, "Relay URL saved", Toast.LENGTH_SHORT).show()
            }
        }

        btnExportRecovery.setOnClickListener {
            authenticateAndShowRecovery()
        }

        btnAddIdentity.setOnClickListener {
            val count = app.identityManager.listIdentities().size
            if (count >= com.glyph.messenger.crypto.IdentityManager.MAX_IDENTITIES) {
                Toast.makeText(this, "Maximum 3 identities reached on this device.", Toast.LENGTH_LONG).show()
            } else {
                startActivity(Intent(this, OnboardingActivity::class.java))
            }
        }
    }

    private fun loadData() {
        val active = app.identityManager.getActiveIdentity()
        if (active != null) {
            txtSettingsUsername.text = "@${active.username}"
            txtSettingsSignKey.text = "Ed25519 Pub: ${active.signPubKeyHex.take(16)}...${active.signPubKeyHex.takeLast(8)}"
            txtSettingsDhKey.text = "X25519 DH Pub: ${active.dhPubKeyHex.take(16)}...${active.dhPubKeyHex.takeLast(8)}"
        }

        editSettingsRelayUrl.setText(app.relayClient.relayBaseUrl)

        val identities = app.identityManager.listIdentities()
        val textBuilder = StringBuilder()
        for (user in identities) {
            val isCurrent = user == active?.username
            textBuilder.append(if (isCurrent) "• @$user (Active)\n" else "• @$user\n")
        }
        txtIdentitiesList.text = textBuilder.toString().trimEnd()
    }

    private fun authenticateAndShowRecovery() {
        val active = app.identityManager.getActiveIdentity() ?: return

        val biometricManager = BiometricManager.from(this)
        val canAuth = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )

        if (canAuth == BiometricManager.BIOMETRIC_SUCCESS) {
            val executor = ContextCompat.getMainExecutor(this)
            val prompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    displayRecoveryDialog(active.recoveryCode)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Toast.makeText(this@SettingsActivity, "Authentication failed: $errString", Toast.LENGTH_SHORT).show()
                }
            })

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Export Recovery Code")
                .setSubtitle("Confirm identity to reveal master recovery key")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build()

            prompt.authenticate(promptInfo)
        } else {
            // Directly display if device has no lock enrolled
            displayRecoveryDialog(active.recoveryCode)
        }
    }

    private fun displayRecoveryDialog(code: String) {
        AlertDialog.Builder(this)
            .setTitle("Master Recovery Code")
            .setMessage("Keep this phrase offline in a safe place:\n\n$code")
            .setPositiveButton("Copy Code") { _, _ ->
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("Glyph Recovery Code", code)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(this, "Copied to clipboard!", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Close", null)
            .show()
    }
}

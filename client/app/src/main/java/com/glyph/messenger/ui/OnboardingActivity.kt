package com.glyph.messenger.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.glyph.messenger.GlyphApp
import com.glyph.messenger.R
import com.glyph.messenger.crypto.IdentityManager
import kotlinx.coroutines.launch

class OnboardingActivity : AppCompatActivity() {

    private lateinit var app: GlyphApp
    private lateinit var editUsername: EditText
    private lateinit var btnClaim: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var txtError: TextView
    private lateinit var layoutClaimForm: LinearLayout
    private lateinit var layoutRecoveryCard: LinearLayout
    private lateinit var txtRecoveryCode: TextView
    private lateinit var btnCopyRecovery: Button
    private lateinit var btnContinueChats: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_onboarding)

        app = application as GlyphApp

        val active = app.identityManager.getActiveIdentity()
        if (active != null) {
            // Already onboarded: unlock with Biometrics/PIN if available
            authenticateAndProceed()
            return
        }

        initViews()
    }

    private fun initViews() {
        editUsername = findViewById(R.id.editUsername)
        btnClaim = findViewById(R.id.btnClaim)
        progressBar = findViewById(R.id.progressBar)
        txtError = findViewById(R.id.txtError)
        layoutClaimForm = findViewById(R.id.layoutClaimForm)
        layoutRecoveryCard = findViewById(R.id.layoutRecoveryCard)
        txtRecoveryCode = findViewById(R.id.txtRecoveryCode)
        btnCopyRecovery = findViewById(R.id.btnCopyRecovery)
        btnContinueChats = findViewById(R.id.btnContinueChats)

        btnClaim.setOnClickListener {
            handleClaim()
        }

        btnContinueChats.setOnClickListener {
            navigateToChatList()
        }
    }

    private fun handleClaim() {
        val username = editUsername.text.toString().trim().lowercase()

        if (!username.matches(Regex("^[a-z0-9_]{3,32}$"))) {
            showError("Username must be 3–32 characters, lowercase letters, numbers, or underscores.")
            return
        }

        hideError()
        setLoading(true)

        lifecycleScope.launch {
            try {
                // 1. Generate identity with MAMA40 assembly core
                val identity = app.identityManager.createIdentity(username)
                val timestamp = System.currentTimeMillis() / 1000

                // 2. Sign claim with Ed25519/MAMA key
                val sigHex = app.identityManager.signClaim(identity, timestamp)

                // 3. Register identity on Relay server
                val result = app.relayClient.claimUsername(
                    username = identity.username,
                    pubkeyHex = identity.signPubKeyHex,
                    sigHex = sigHex,
                    timestamp = timestamp
                )

                setLoading(false)

                if (result.isSuccess) {
                    // Show one-time recovery code
                    layoutClaimForm.visibility = View.GONE
                    layoutRecoveryCard.visibility = View.VISIBLE
                    txtRecoveryCode.text = identity.recoveryCode

                    btnCopyRecovery.setOnClickListener {
                        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        val clip = ClipData.newPlainText("Glyph Recovery Code", identity.recoveryCode)
                        clipboard.setPrimaryClip(clip)
                        Toast.makeText(this@OnboardingActivity, "Recovery code copied to clipboard!", Toast.LENGTH_SHORT).show()
                    }
                } else {
                    val err = result.exceptionOrNull()?.message ?: "Claim failed"
                    showError(err)
                }
            } catch (e: Exception) {
                setLoading(false)
                showError("Error: ${e.message}")
            }
        }
    }

    private fun authenticateAndProceed() {
        val biometricManager = BiometricManager.from(this)
        val canAuthenticate = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )

        if (canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS) {
            val executor = ContextCompat.getMainExecutor(this)
            val prompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    navigateToChatList()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    // If user cancels or device lock fails, still allow pass or exit
                    if (errorCode == BiometricPrompt.ERROR_USER_CANCELED || errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                        finish()
                    } else {
                        navigateToChatList()
                    }
                }
            })

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock Glyph")
                .setSubtitle("Confirm identity to access encrypted chats")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build()

            prompt.authenticate(promptInfo)
        } else {
            // No biometric/PIN enrolled, proceed directly
            navigateToChatList()
        }
    }

    private fun navigateToChatList() {
        startActivity(Intent(this, ChatListActivity::class.java))
        finish()
    }

    private fun setLoading(loading: Boolean) {
        btnClaim.isEnabled = !loading
        progressBar.visibility = if (loading) View.VISIBLE else View.GONE
    }

    private fun showError(msg: String) {
        txtError.text = msg
        txtError.visibility = View.VISIBLE
    }

    private fun hideError() {
        txtError.visibility = View.GONE
    }
}

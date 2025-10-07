package com.schematics.epochseal

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AlertDialog
import android.os.Bundle
import android.widget.Toast
import com.schematics.epochseal.databinding.ActivityMainBinding

const val fekFLAG = "SCH25{UthinkSO?_=P}"

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var remainingAttempts = 3

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.buttonCheckPIN.setOnClickListener {
            checkPin()
        }
    }

    private fun checkPin() {
        if (remainingAttempts <= 0) {
            Toast.makeText(this, "Too many failed attempts. App is locked.", Toast.LENGTH_LONG).show()
            return
        }

        val enteredPin = binding.inputPIN.text.toString()

        if (enteredPin.isEmpty()) {
            Toast.makeText(this, "PIN cannot be empty", Toast.LENGTH_SHORT).show()
            return
        } else if (enteredPin.length != 6 || !enteredPin.all { it.isDigit() }) {
            Toast.makeText(this, "PIN must be 6 digits", Toast.LENGTH_SHORT).show()
            return
        }

        val result = checkPinNative(enteredPin.toInt())

        // If the result is not "Try again", it's the flag (either real or fake from anti-debug).
        if (result != "Try again") {
            AlertDialog.Builder(this)
                .setTitle("SUCCESS! 🎉")
                .setMessage("Here is your flag:\n$result")
                .setNeutralButton("Copy") { _, _ ->
                    val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    val clip = ClipData.newPlainText("flag", result)
                    clipboard.setPrimaryClip(clip)
                    Toast.makeText(this, "Flag copied to clipboard!", Toast.LENGTH_SHORT).show()
                }
                .setPositiveButton("OK") { dialog, _ ->
                    dialog.dismiss()
                }
                .setCancelable(false)
                .show()

            binding.buttonCheckPIN.isEnabled = false
            binding.inputPIN.isEnabled = false

        } else {
            remainingAttempts--
            if (remainingAttempts > 0) {
                val message = "Try again. $remainingAttempts attempts remaining."
                Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Too many failed attempts. App is locked.", Toast.LENGTH_LONG).show()
                binding.buttonCheckPIN.isEnabled = false
                binding.inputPIN.isEnabled = false
            }
        }
    }


    private external fun checkPinNative(pin: Int): String

    companion object {
        init {
            System.loadLibrary("epochseal")
        }
    }
}
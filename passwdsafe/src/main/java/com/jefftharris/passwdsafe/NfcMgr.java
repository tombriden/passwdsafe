/*
 * Copyright (©) 2014 Jeff Harris <jefftharris@gmail.com>
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */
package com.jefftharris.passwdsafe;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.Ndef;
import android.nfc.tech.NdefFormatable;
import android.os.Build;
import android.os.CountDownTimer;
import android.os.Parcelable;
import android.util.Base64;
import android.widget.Toast;

import com.jefftharris.passwdsafe.lib.PasswdSafeUtil;
import com.jefftharris.passwdsafe.util.NfcState;

import org.pwsafe.lib.Util;

import java.io.ByteArrayOutputStream;
import java.security.spec.KeySpec;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * The YubikeyMgr class encapsulates the interaction with a YubiKey
 */
@TargetApi(Build.VERSION_CODES.GINGERBREAD_MR1)
public class NfcMgr
{
    private static final String TAG = "NfcMgr";

    private User itsUser = null;
    private boolean itsIsRegistered = false;
    private PendingIntent itsTagIntent = null;
    private CountDownTimer itsTimer = null;

    protected interface User
    {
        /// Get the activity using the key
        Activity getActivity();

        /// Finish interaction with the key
        void finish(String password, Exception e);

        /// Handle an update on the timer until the start times out
        void timerTick(@SuppressWarnings("SameParameterValue") int totalTime,
                       int remainingTime);
    }

    /** Get the state of support for the Yubikey */
    public NfcState getState(Activity act)
    {
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(act);
        if (adapter == null) {
            return NfcState.UNAVAILABLE;
        } else if (!adapter.isEnabled()) {
            return NfcState.DISABLED;
        }
        return NfcState.ENABLED;
    }

    private static String encrypt(String password, byte[] salt, String plaintext) throws Exception {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 500, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secret);

        byte[] cipherText = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return new String(Base64.encode(cipherText, 0));
    }

    private static String decrypt(String password, byte[] salt, String encrypted) throws Exception {

        SecretKeyFactory factory = SecretKeyFactory.getInstance(
                "PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 500, 256);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secret);

        byte[] cipherText = Base64.decode(encrypted.getBytes(), 0);
        String plaintext = new String(cipher.doFinal(cipherText), "UTF-8");
        return plaintext;
    }

    /// Start the interaction with the NfcTag
    public void start(User user)
    {
        if (itsUser != null) {
            stop();
        }

        itsUser = user;
        Activity act = itsUser.getActivity();
        if (itsTagIntent == null) {
            Intent intent = new Intent(act, act.getClass());
            intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
            itsTagIntent = PendingIntent.getActivity(act, 0, intent, 0);
        }

        if (!itsIsRegistered) {
            NfcAdapter adapter = NfcAdapter.getDefaultAdapter(act);
            if (adapter == null) {
                Toast.makeText(act, "NO NFC", Toast.LENGTH_LONG).show();
                return;
            }

            if (!adapter.isEnabled()) {
                Toast.makeText(act, "NFC DISABLED", Toast.LENGTH_LONG).show();
                return;
            }

            IntentFilter iso =
                    new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);
            adapter.enableForegroundDispatch(
                    act, itsTagIntent, new IntentFilter[] { iso },
                    new String[][]
                            { new String[] { IsoDep.class.getName() }, { Ndef.class.getName()} });
            itsIsRegistered = true;
        }

        itsTimer = new CountDownTimer(30 * 1000, 1 * 1000) {
            @Override
            public void onFinish()
            {
                stop();
            }

            @Override
            public void onTick(long millisUntilFinished)
            {
                itsUser.timerTick(30, (int)(millisUntilFinished / 1000));
            }
        };
        itsTimer.start();
    }

    /** Handle a pause of the activity */
    public void onPause()
    {
        if (itsUser == null) {
            return;
        }
        Activity act = itsUser.getActivity();

        if (itsIsRegistered) {
            NfcAdapter adapter = NfcAdapter.getDefaultAdapter(act);
            if ((adapter == null) || !adapter.isEnabled()) {
                return;
            }

            adapter.disableForegroundDispatch(act);
            itsIsRegistered = false;
        }

        if (itsTagIntent != null) {
            itsTagIntent.cancel();
            itsTagIntent = null;
        }
    }

    /// Stop the interaction with the key
    public void stop()
    {
        onPause();
        stopUser(null, null);
        itsTimer = null;
        itsUser = null;
    }

    /// Handle the intent for when the key is discovered
    public void handleKeyIntent(Intent intent)
    {
        if (!NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())) {
            return;
        }

        PasswdSafeUtil.dbginfo(TAG, "calculate");
        Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if ((tag == null) || (itsUser == null)) {
            return;
        }

        try {
            String pwstr = null;
            if(intent.getBooleanExtra("writeTag", false)){

                pwstr = intent.getExtras().getString("pwsafePass");
                String encryptionPass = UUID.randomUUID().toString();
                String encryptedPwsafePass = encrypt(encryptionPass, tag.getId(), pwstr);
                String encryptedEncryptionPass = encrypt(encryptedPwsafePass, tag.getId(),
                        encryptionPass);

                short TNF_MIME_MEDIA = 2;
                NdefRecord[] records = { new NdefRecord(TNF_MIME_MEDIA,
                        "application/nfckey".getBytes(),
                        "passwdsafe".getBytes(),
                        encryptedPwsafePass.getBytes()) };

                NdefMessage message = new NdefMessage(records);
                Ndef ndef = Ndef.get(tag);

                if(ndef != null) {
                    ndef.connect();
                    ndef.writeNdefMessage(message);
                    ndef.close();
                }
                else{
                    NdefFormatable formatable = NdefFormatable.get(tag);
                    if (formatable != null) {
                        formatable.connect();
                        formatable.format(message);
                        formatable.close();
                    }
                }
                //Log.i("passwdsafe", "Written to tag successfully");
                SharedPreferences sharedPref = itsUser.getActivity().getPreferences(
                        Context.MODE_PRIVATE);
                SharedPreferences.Editor editor = sharedPref.edit();
                editor.putString("encryptionkey", encryptedEncryptionPass);
                editor.commit();
            }
            else{
                Parcelable[] rawMsgs = intent.getParcelableArrayExtra(
                        NfcAdapter.EXTRA_NDEF_MESSAGES);
                NdefMessage msg;
                if (rawMsgs != null && rawMsgs.length > 0) {
                    msg = (NdefMessage) rawMsgs[0];

                    NdefRecord[] contentRecs = msg.getRecords();
                    for (NdefRecord rec : contentRecs) {
                        String id = new String(rec.getId(), "UTF-8");
                        if (id.equals("passwdsafe")) {
                            String encryptedPass = new String(
                                    rec.getPayload(), "UTF-8");
                            SharedPreferences sharedPref = itsUser
                                    .getActivity().getPreferences(
                                            Context.MODE_PRIVATE);

                            String encryptedEncryptionPass = sharedPref
                                    .getString("encryptionkey", "");
                            String encryptionPass = decrypt(
                                    encryptedPass, tag.getId(),
                                    encryptedEncryptionPass);
                            pwstr = decrypt(
                                    encryptionPass, tag.getId(),
                                    encryptedPass);

                            break;
                        }
                    }
                }
            }
            stopUser(pwstr, null);
        }catch(Exception e){
            PasswdSafeUtil.dbginfo(TAG, e, "handleKeyIntent");
            stopUser(null, e);
        }
    }

    /**
     * Stop interaction with the user
     */
    protected void stopUser(String password, Exception e)
    {
        if (itsTimer != null) {
            itsTimer.cancel();
        }
        if (itsUser != null) {
            itsUser.finish(password, e);
        }
    }
}

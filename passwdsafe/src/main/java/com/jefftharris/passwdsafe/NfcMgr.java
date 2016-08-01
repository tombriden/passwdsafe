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

    protected User itsUser = null;
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

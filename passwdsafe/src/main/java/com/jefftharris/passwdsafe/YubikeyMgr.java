/*
 * Copyright (©) 2017 Jeff Harris <jefftharris@gmail.com>
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */
package com.jefftharris.passwdsafe;

import java.io.ByteArrayOutputStream;

import org.pwsafe.lib.Util;

import android.annotation.TargetApi;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;

import com.jefftharris.passwdsafe.lib.PasswdSafeUtil;
import com.jefftharris.passwdsafe.lib.Utils;


/**
 * The YubikeyMgr class encapsulates the interaction with a YubiKey
 */
@TargetApi(Build.VERSION_CODES.GINGERBREAD_MR1)
public class YubikeyMgr extends NfcMgr
{
    /// Command to select the app running on the key
    private static final byte[] SELECT_CMD =
        {0x00, (byte) 0xA4, 0x04, 0x00, 0x07,
         (byte) 0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x00};
    /// Command to perform a hash operation
    private static final byte[] HASH_CMD = {0x00, 0x01, 0x00, 0x00 };

    private static final byte SLOT_CHAL_HMAC1 = 0x30;
    private static final byte SLOT_CHAL_HMAC2 = 0x38;

    private static final int SHA1_MAX_BLOCK_SIZE = 64;

    private static final String TAG = "YubikeyMgr";
    private User itsUser = null;

    public interface User extends NfcMgr.User
    {
        /// Get the password to be sent to the key
        String getUserPassword();

        /// Get the slot number to use on the key
        int getSlotNum();
    }

    /// Handle the intent for when the key is discovered
    @Override
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
            IsoDep isotag = IsoDep.get(tag);
            isotag.connect();
            try {
                byte[] resp = isotag.transceive(SELECT_CMD);
                checkResponse(resp);

                String pw = itsUser.getUserPassword();
                ByteArrayOutputStream cmd = new ByteArrayOutputStream();
                cmd.write(HASH_CMD);

                // Placeholder for length
                byte datalen;
                cmd.write(0);

                int pwlen = pw.length();
                if (pwlen > 0) {
                    if (pwlen > SHA1_MAX_BLOCK_SIZE / 2) {
                        pwlen = SHA1_MAX_BLOCK_SIZE / 2;
                    }
                    // Chars are encoded as little-endian UTF-16.  A trailing
                    // zero must be skipped as the PC API will skip it.
                    datalen = 0;
                    for (int i = 0; i < pwlen - 1; i++) {
                        datalen = 2;
                        char c = pw.charAt(i);
                        cmd.write(c & 0xff);
                        cmd.write((c >> 8) & 0xff);
                    }

                    char c = pw.charAt(pwlen - 1);
                    cmd.write(c & 0xff);
                    ++datalen;
                    int last = (c >> 8) & 0xff;
                    if (last != 0) {
                        cmd.write(last);
                        ++datalen;
                    }
                } else {
                    // Empty password needs a single null byte
                    datalen = 1;
                    cmd.write(0);
                }

                byte[] cmdBytes = cmd.toByteArray();
                int slot = itsUser.getSlotNum();
                if (slot == 1) {
                    cmdBytes[2] = SLOT_CHAL_HMAC1;
                } else {
                    cmdBytes[2] = SLOT_CHAL_HMAC2;
                }
                cmdBytes[HASH_CMD.length] = datalen;
                //                PasswdSafeUtil.dbginfo(TAG, "cmd: %s",
                //                                       Util.bytesToHex(cmdbytes));

                resp = isotag.transceive(cmdBytes);
                checkResponse(resp);

                // Prune response bytes and convert
                String pwstr = Util.bytesToHex(resp, 0, resp.length - 2);
                //                PasswdSafeUtil.dbginfo(TAG, "Pw: " + pwstr);
                stopUser(pwstr, null);

            } finally {
                Utils.closeStreams(isotag);
            }
        }catch(Exception e){
            PasswdSafeUtil.dbginfo(TAG, e, "handleKeyIntent");
            stopUser(null, e);
        }
    }

    /// Check for a valid response
    private static void checkResponse(byte[] resp) throws Exception
    {
        if ((resp.length >= 2) &&
                (resp[resp.length - 2] == (byte)0x90) &&
                (resp[resp.length - 1] == 0x00)) {
            return;
        }

        throw new Exception("Invalid response: " +
                            Util.bytesToHex(resp));
    }

}

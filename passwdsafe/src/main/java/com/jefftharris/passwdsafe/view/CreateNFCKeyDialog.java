package com.jefftharris.passwdsafe.view;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.PendingIntent;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import com.jefftharris.passwdsafe.R;
import com.jefftharris.passwdsafe.lib.view.AbstractDialogClickListener;
import com.jefftharris.passwdsafe.lib.view.GuiUtils;

/**
 * Created by tom on 04/10/15.
 */
public class CreateNFCKeyDialog {

    private final Activity itsActivity;
    private AlertDialog itsDialog;

    /** Constructor */
    public CreateNFCKeyDialog(Activity act)
    {
        itsActivity = act;
    }

    /** Create the dialog */
    public Dialog create()
    {
        LayoutInflater factory = LayoutInflater.from(itsActivity);
        @SuppressLint("InflateParams")
        View nfcKeyView = factory.inflate(R.layout.create_nfc_key, null);
        AbstractDialogClickListener dlgClick =
                new AbstractDialogClickListener()
                {
                    @Override
                    public void onOkClicked(DialogInterface dialog)
                    {
                        Dialog d = (Dialog)dialog;

                        EditText pwsafePassInput =
                                (EditText)d.findViewById(R.id.passwd_edit);

                        EditText encryptionPassInput =
                                (EditText)d.findViewById(R.id.encryption_edit);

                        String pwsafePass = pwsafePassInput.getText().toString();
                        String encryptionPass = encryptionPassInput.getText().toString();

                        Intent intent = new Intent(itsActivity, itsActivity.getClass());
                        intent.putExtra("pwsafe_pass", pwsafePass);
                        intent.putExtra("encryption_pass", encryptionPass);
                        intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);

                        PendingIntent pendingIntent = PendingIntent.getActivity(itsActivity, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);
                        IntentFilter tagDetected = new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED);
                        tagDetected.addCategory(Intent.CATEGORY_DEFAULT);
                        IntentFilter writeTagFilters[] = new IntentFilter[] { tagDetected };

                        NfcAdapter.getDefaultAdapter(itsActivity).enableForegroundDispatch(itsActivity, pendingIntent, writeTagFilters, null);
                    }
                };

        TextView pwsafePassEdit =
                (TextView)nfcKeyView.findViewById(R.id.passwd_edit);
        PasswordVisibilityMenuHandler.set(pwsafePassEdit);

        AlertDialog.Builder alert = new AlertDialog.Builder(itsActivity)
                .setTitle(R.string.create_nfc_key_title)
                .setView(nfcKeyView)
                .setPositiveButton(R.string.ok, dlgClick)
                .setNegativeButton(R.string.cancel, dlgClick)
                .setOnCancelListener(dlgClick);
        itsDialog = alert.create();
        GuiUtils.setupDialogKeyboard(itsDialog, pwsafePassEdit, pwsafePassEdit,
                itsActivity);
        return itsDialog;
    }

    /** Handle a new intent. **/
    public void onNewIntent(Intent intent)
    {
    }

    /** Set visibility of a field */
    private static void setVisibility(int id, boolean visible, View parent)
    {
        View v = parent.findViewById(id);
        v.setVisibility(visible ? View.VISIBLE : View.GONE);
    }

    /** Set visibility of a field */
    private static void setVisibility(int id,
                                      boolean visible,
                                      AlertDialog parent)
    {
        View v = parent.findViewById(id);
        v.setVisibility(visible ? View.VISIBLE : View.GONE);
    }
}

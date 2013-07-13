/*
 * Copyright (©) 2013 Jeff Harris <jefftharris@gmail.com> All rights reserved.
 * Use of the code is allowed under the Artistic License 2.0 terms, as specified
 * in the LICENSE file distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */
package com.jefftharris.passwdsafe.sync;

import java.util.List;

import android.accounts.Account;
import android.content.ContentProviderClient;
import android.content.ContentResolver;
import android.content.Context;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.text.format.DateUtils;
import android.util.Log;

import com.google.android.gms.auth.GoogleAuthUtil;
import com.google.api.client.googleapis.extensions.android.accounts.GoogleAccountManager;
import com.google.api.client.googleapis.extensions.android.gms.auth.GoogleAccountCredential;
import com.jefftharris.passwdsafe.lib.PasswdSafeContract;
import com.jefftharris.passwdsafe.lib.PasswdSafeUtil;
import com.jefftharris.passwdsafe.lib.ProviderType;

/**
 *  The ProviderSyncer class syncs password files from Google Drive
 */
public class ProviderSyncer
{
    private static final String TAG = "ProviderSyncer";

    private final Context itsContext;
    private final Account itsAccount;
    private final SyncDb itsSyncDb;

    /** Constructor */
    public ProviderSyncer(Context context,
                        ContentProviderClient provider,
                        Account account)
    {
        itsContext = context;
        itsAccount = account;
        itsSyncDb = new SyncDb(itsContext);
    }


    /** Add a provider for an account */
    public static long addProvider(String acctName, ProviderType type,
                                   SQLiteDatabase db, Context ctx)
        throws SQLException
    {
        Log.i(TAG, "Add provider: " + acctName);
        int freq = ProviderSyncFreqPref.DEFAULT.getFreq();
        long id = SyncDb.addProvider(acctName, type, freq, db);

        Account acct = getProviderAcct(acctName, type, ctx);
        if (acct != null) {
            ContentResolver.setSyncAutomatically(
                    acct, PasswdSafeContract.AUTHORITY, true);
            ContentResolver.addPeriodicSync(
                    acct, PasswdSafeContract.AUTHORITY, new Bundle(), freq);
            ContentResolver.requestSync(acct, PasswdSafeContract.AUTHORITY,
                                        new Bundle());
        }
        ctx.getContentResolver().notifyChange(
                PasswdSafeContract.Providers.CONTENT_URI, null);
        return id;
    }


    /** Delete the provider for the account */
    public static void deleteProvider(SyncDb.DbProvider provider,
                                      SQLiteDatabase db,
                                      Context ctx)
        throws SQLException
    {
        List<SyncDb.DbFile> dbfiles = SyncDb.getFiles(provider.itsId, db);
        for (SyncDb.DbFile dbfile: dbfiles) {
            ctx.deleteFile(dbfile.itsLocalFile);
        }

        SyncDb.deleteProvider(provider.itsId, db);

        switch (provider.itsType) {
        case GDRIVE: {
            try {
                GoogleAccountCredential credential =
                        GDriveProvider.getAcctCredential(ctx);
                String token = GoogleAuthUtil.getToken(ctx, provider.itsAcct,
                                                       credential.getScope());
                PasswdSafeUtil.dbginfo(TAG, "Remove token for %s: %s",
                                       provider.itsAcct, token);
                if (token != null) {
                    GoogleAuthUtil.invalidateToken(ctx, token);
                }
            } catch (Exception e) {
                PasswdSafeUtil.dbginfo(TAG, e, "No auth token for %s",
                                       provider.itsAcct);
            }
            break;
        }
        }
        Account acct = getProviderAcct(provider.itsAcct, provider.itsType, ctx);
        if (acct != null) {
            ContentResolver.removePeriodicSync(acct,
                                               PasswdSafeContract.AUTHORITY,
                                               new Bundle());
            ContentResolver.setSyncAutomatically(acct,
                                                 PasswdSafeContract.AUTHORITY,
                                                 false);
        }
        ctx.getContentResolver().notifyChange(PasswdSafeContract.CONTENT_URI,
                                              null);
    }


    /** Update the sync frequency for a provider */
    public static void updateSyncFreq(SyncDb.DbProvider provider,
                                      int freq,
                                      SQLiteDatabase db,
                                      Context ctx)
            throws SQLException
    {
        SyncDb.updateProviderSyncFreq(provider.itsId, freq, db);

        Account acct = getProviderAcct(provider.itsAcct, provider.itsType, ctx);
        if (acct != null) {
            ContentResolver.removePeriodicSync(acct,
                                               PasswdSafeContract.AUTHORITY,
                                               new Bundle());
            if (freq > 0) {
                ContentResolver.addPeriodicSync(acct,
                                                PasswdSafeContract.AUTHORITY,
                                                new Bundle(), freq);
            }
        }
    }


    /** Validate the provider accounts */
    public static void validateAccounts(SQLiteDatabase db, Context ctx)
            throws SQLException
    {
        PasswdSafeUtil.dbginfo(TAG, "Validating accounts");

        List<SyncDb.DbProvider> providers = SyncDb.getProviders(db);
        for (SyncDb.DbProvider provider: providers) {
            Account acct = getProviderAcct(provider.itsAcct, provider.itsType,
                                           ctx);
            if (acct == null) {
                deleteProvider(provider, db, ctx);
            }
        }
        ctx.getContentResolver().notifyChange(PasswdSafeContract.CONTENT_URI,
                                              null);
    }

    /** Get the filename for a local file */
    public static String getLocalFileName(long fileId)
    {
        return "syncfile-" + Long.toString(fileId);
    }

    /** Close the syncer */
    public void close()
    {
        itsSyncDb.close();
    }


    /** Perform synchronization */
    public void performSync(boolean manual)
    {
        PasswdSafeUtil.dbginfo(TAG, "Performing sync for %s, manual: %b",
                               itsAccount.name, manual);

        /** Check if the syncing account is a valid provider */
        SQLiteDatabase db = itsSyncDb.getDb();
        SyncDb.DbProvider provider = null;
        try {
            db.beginTransaction();
            provider = SyncDb.getProvider(itsAccount.name, db);
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
        if (provider == null) {
            PasswdSafeUtil.dbginfo(TAG, "No provider for %s", itsAccount.name);
            return;
        }

        Provider providerImpl = null;
        switch (provider.itsType) {
        case GDRIVE: {
            providerImpl = new GDriveProvider(itsContext);
            break;
        }
        }

        SyncLogRecord logrec = new SyncLogRecord(itsAccount.name, manual);
        try {
            providerImpl.sync(itsAccount, provider, db, logrec);
        } catch (Exception e) {
            Log.e(TAG, "Sync error", e);
            logrec.addFailure(e);
        }
        PasswdSafeUtil.dbginfo(TAG, "Sync finished for %s", itsAccount.name);
        logrec.setEndTime();

        try {
            db.beginTransaction();
            Log.i(TAG, logrec.toString(itsContext));
            SyncDb.deleteSyncLogs(
                    System.currentTimeMillis() - 2 * DateUtils.WEEK_IN_MILLIS,
                    db);
            SyncDb.addSyncLog(logrec, db);
            db.setTransactionSuccessful();
        } catch (Exception e) {
            Log.e(TAG, "Sync write log error", e);
        } finally {
            db.endTransaction();
        }
    }

    // TODO: show folders


    /** Get the account for a provider's name and type */
    private static Account getProviderAcct(String acctName, ProviderType type,
                                           Context ctx)
    {
        switch (type) {
        case GDRIVE: {
            GoogleAccountManager acctMgr = new GoogleAccountManager(ctx);
            return acctMgr.getAccountByName(acctName);
        }
        }
        return null;
    }
}
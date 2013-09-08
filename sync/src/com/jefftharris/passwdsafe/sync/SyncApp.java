/*
 * Copyright (©) 2013 Jeff Harris <jefftharris@gmail.com> All rights reserved.
 * Use of the code is allowed under the Artistic License 2.0 terms, as specified
 * in the LICENSE file distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */
package com.jefftharris.passwdsafe.sync;

import android.accounts.Account;
import android.app.Activity;
import android.app.AlarmManager;
import android.app.Application;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import com.dropbox.sync.android.DbxAccount;
import com.dropbox.sync.android.DbxAccountManager;
import com.dropbox.sync.android.DbxException;
import com.dropbox.sync.android.DbxFileSystem;
import com.dropbox.sync.android.DbxFileSystem.PathListener;
import com.dropbox.sync.android.DbxPath;
import com.jefftharris.passwdsafe.lib.PasswdSafeUtil;

/**
 *  Application class for PasswdSafe Sync
 */
public class SyncApp extends Application
{
    public static final String ACTION_SYNC_EXPIRATION_TIMEOUT =
            "com.jefftharris.passwdsafe.action.SYNC_EXPIRATION_TIMEOUT";

    private static final String DROPBOX_SYNC_APP_KEY = "ncrre47fqpcu42z";
    private static final String DROPBOX_SYNC_APP_SECRET = "7wxt4myb2qut395";

    private static final String TAG = "SyncApp";

    private SyncDb itsSyncDb = null;
    private Handler itsTimerHandler = null;
    private DbxAccountManager itsDropboxAcctMgr = null;
    private DbxFileSystem itsDropboxFs = null;
    private boolean itsDropboxSyncInProgress = false;
    private Runnable itsDropboxSyncProgressHandler = null;
    private PathListener itsDropboxPathListener = null;
    private Runnable itsDropboxSyncEndHandler = null;
    private PendingIntent itsSyncTimeoutIntent = null;

    /* (non-Javadoc)
     * @see android.app.Application#onCreate()
     */
    @Override
    public void onCreate()
    {
        PasswdSafeUtil.dbginfo(TAG, "onCreate");
        super.onCreate();

        itsSyncDb = new SyncDb(this);
        itsTimerHandler = new Handler(Looper.getMainLooper());
        itsDropboxAcctMgr =
                DbxAccountManager.getInstance(getApplicationContext(),
                                              DROPBOX_SYNC_APP_KEY,
                                              DROPBOX_SYNC_APP_SECRET);
        updateDropboxAcct();
    }


    /* (non-Javadoc)
     * @see android.app.Application#onTerminate()
     */
    @Override
    public void onTerminate()
    {
        PasswdSafeUtil.dbginfo(TAG, "onTerminate");
        if (itsSyncTimeoutIntent != null) {
            AlarmManager alarmMgr =
                    (AlarmManager)getSystemService(Context.ALARM_SERVICE);
            alarmMgr.cancel(itsSyncTimeoutIntent);
        }
        itsSyncDb.close();
        super.onTerminate();
    }


    /** Get the Sync application */
    public static SyncApp get(Context ctx)
    {
        return (SyncApp)ctx.getApplicationContext();
    }


    /** Acquire the SyncDb */
    public static SyncDb acquireSyncDb(Context ctx)
    {
        SyncApp app = SyncApp.get(ctx);
        app.itsSyncDb.acquire();
        return app.itsSyncDb;
    }


    /** Start the process of linking to a Dropbox account */
    public void startDropboxLink(Activity act, int requestCode)
    {
        itsDropboxAcctMgr.startLink(act, requestCode);
    }


    /** Finish the process of linking a Dropbox account */
    public void finishDropboxLink()
    {
        updateDropboxAcct();
    }


    /** Unlink the Dropbox account */
    public void unlinkDropbox()
    {
        itsDropboxAcctMgr.unlink();
        updateDropboxAcct();
    }


    /** Sync Dropbox */
    public void syncDropbox(final boolean manual)
    {
        DbxFileSystem fs = getDropboxFs();
        if (fs == null) {
            PasswdSafeUtil.dbginfo(TAG, "syncDropbox no fs");
        }

        PasswdSafeUtil.dbginfo(TAG, "syncDropbox");
        if (itsDropboxPathListener != null) {
            return;
        }
        itsDropboxPathListener = new PathListener()
        {
            @Override
            public void onPathChange(DbxFileSystem fs,
                                     DbxPath path, Mode mode)
            {
                PasswdSafeUtil.dbginfo(TAG, "syncDropbox path change");
                doDropboxSync(manual);
            }
        };

        if (itsDropboxSyncEndHandler != null) {
            itsTimerHandler.removeCallbacks(itsDropboxSyncEndHandler);
        }
        itsDropboxSyncEndHandler = new Runnable()
        {
            @Override
            public void run()
            {
                PasswdSafeUtil.dbginfo(TAG, "syncDropbox end timer");
                DbxFileSystem fs = getDropboxFs();
                if ((fs != null) && (itsDropboxPathListener != null)) {
                    fs.removePathListenerForAll(itsDropboxPathListener);
                }
                itsDropboxPathListener = null;
                itsDropboxSyncEndHandler = null;
            }
        };
        itsTimerHandler.postDelayed(itsDropboxSyncEndHandler, 60 * 1000);
        fs.addPathListener(itsDropboxPathListener, DbxPath.ROOT,
                           PathListener.Mode.PATH_OR_DESCENDANT);
        doDropboxSync(manual);
    }


    /** Get the Dropbox account; null if no account is linked */
    public DbxAccount getDropboxAcct()
    {
        return itsDropboxAcctMgr.getLinkedAccount();
    }


    /** Get the Dropbox filesystem; null if no account is linked */
    public DbxFileSystem getDropboxFs()
    {
        return itsDropboxFs;
    }


    /** Update after a Dropbox account change */
    private void updateDropboxAcct()
    {
        DbxAccount acct = itsDropboxAcctMgr.getLinkedAccount();

        boolean shouldHaveAlarm = (acct != null);
        boolean haveAlarm = (itsSyncTimeoutIntent != null);

        PasswdSafeUtil.dbginfo(TAG, "updateDropboxAcct should %b have %b",
                               shouldHaveAlarm, haveAlarm);
        if (shouldHaveAlarm && !haveAlarm) {
            acct.addListener(new DbxAccount.Listener()
            {
                @Override
                public void onAccountChange(DbxAccount acct)
                {
                    PasswdSafeUtil.dbginfo(TAG, "Dropbox acct change");
                    doDropboxSync(false);
                }
            });

            Intent timeoutIntent = new Intent(ACTION_SYNC_EXPIRATION_TIMEOUT);
            itsSyncTimeoutIntent = PendingIntent.getBroadcast(
                    this, 0, timeoutIntent, PendingIntent.FLAG_CANCEL_CURRENT);
            AlarmManager alarmMgr =
                    (AlarmManager)getSystemService(Context.ALARM_SERVICE);
            long interval = 15 * 60 * 1000;
            alarmMgr.setInexactRepeating(AlarmManager.RTC,
                                         System.currentTimeMillis() + interval,
                                         interval, itsSyncTimeoutIntent);

            try {
                itsDropboxFs = DbxFileSystem.forAccount(acct);
                syncDropbox(false);
            } catch (DbxException e) {
                Log.e(TAG, "updateDropboxAcct failure", e);
            }
        } else if (!shouldHaveAlarm && haveAlarm) {
            itsDropboxFs = null;
            itsSyncTimeoutIntent.cancel();
            itsSyncTimeoutIntent = null;
        }
    }


    /** Check whether to start a dropbox sync */
    private void doDropboxSync(final boolean manual)
    {
        if (itsDropboxSyncProgressHandler != null) {
            return;
        }
        if (itsDropboxSyncInProgress) {
            itsDropboxSyncProgressHandler = new Runnable()
            {
                public void run()
                {
                    PasswdSafeUtil.dbginfo(TAG, "doDropboxSync timer expired");
                    itsDropboxSyncProgressHandler = null;
                    doDropboxSync(manual);
                }
            };
            PasswdSafeUtil.dbginfo(TAG, "doDropboxSync start timer");
            itsTimerHandler.postDelayed(itsDropboxSyncProgressHandler, 15000);
        } else {
            PasswdSafeUtil.dbginfo(TAG, "doDropboxSync start");
            new DropboxSyncer(manual).execute();
        }
    }


    /** Background syncer for Dropbox */
    private class DropboxSyncer extends AsyncTask<Void, Void, Void>
    {
        private final boolean itsIsManual;

        /** Constructor */
        public DropboxSyncer(boolean manual)
        {
            itsIsManual = manual;
            itsDropboxSyncInProgress = true;
        }

        /* (non-Javadoc)
         * @see android.os.AsyncTask#doInBackground(Params[])
         */
        @Override
        protected Void doInBackground(Void... params)
        {
            DbxAccount acct = getDropboxAcct();
            if (acct != null) {
                ProviderSyncer syncer = new ProviderSyncer(
                        SyncApp.this, new Account(acct.getUserId(),
                                                  SyncDb.DROPBOX_ACCOUNT_TYPE));
                syncer.performSync(itsIsManual);
            }
            return null;
        }

        /* (non-Javadoc)
         * @see android.os.AsyncTask#onPostExecute(java.lang.Object)
         */
        @Override
        protected void onPostExecute(Void result)
        {
            super.onPostExecute(result);
            itsDropboxSyncInProgress = false;
        }
    }
}

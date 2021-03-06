/*
 * Copyright (©) 2017 Jeff Harris <jefftharris@gmail.com>
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */
package com.jefftharris.passwdsafe.sync.owncloud;

import java.util.List;
import java.util.concurrent.TimeUnit;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerFuture;
import android.app.Activity;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v4.app.FragmentActivity;
import android.text.TextUtils;
import android.util.Log;

import com.jefftharris.passwdsafe.lib.ApiCompat;
import com.jefftharris.passwdsafe.lib.ObjectHolder;
import com.jefftharris.passwdsafe.lib.PasswdSafeUtil;
import com.jefftharris.passwdsafe.lib.ProviderType;
import com.jefftharris.passwdsafe.sync.R;
import com.jefftharris.passwdsafe.sync.lib.AbstractSyncTimerProvider;
import com.jefftharris.passwdsafe.sync.lib.AccountChooserDlg;
import com.jefftharris.passwdsafe.sync.lib.DbProvider;
import com.jefftharris.passwdsafe.sync.lib.NewAccountTask;
import com.jefftharris.passwdsafe.sync.lib.SyncConnectivityResult;
import com.jefftharris.passwdsafe.sync.lib.SyncDb;
import com.jefftharris.passwdsafe.sync.lib.SyncIOException;
import com.jefftharris.passwdsafe.sync.lib.SyncLogRecord;
import com.owncloud.android.lib.common.OwnCloudClient;
import com.owncloud.android.lib.common.OwnCloudClientFactory;
import com.owncloud.android.lib.common.OwnCloudCredentialsFactory;
import com.owncloud.android.lib.common.accounts.AccountTypeUtils;
import com.owncloud.android.lib.common.network.NetworkUtils;

/**
 *  Implements a provider for the ownCloud service
 */
public class OwncloudProvider extends AbstractSyncTimerProvider
{
    private static final String PREF_AUTH_ACCOUNT = "owncloudAccount";
    private static final String PREF_CERT_ALIAS = "owncloudCertAlias";
    private static final String PREF_URL = "owncloudUrl";
    private static final String PREF_USE_HTTPS = "owncloudUseHttps";

    private static final String TAG = "OwncloudProvider";

    private String itsAccountName = null;
    private String itsUserName = null;
    private Uri itsUrl = null;
    private boolean itsIsSyncAuthError= false;

    /** Constructor */
    public OwncloudProvider(Context ctx)
    {
        super(ProviderType.OWNCLOUD, ctx, TAG);
    }

    /* (non-Javadoc)
     * @see com.jefftharris.passwdsafe.sync.lib.Provider#init()
     */
    @Override
    public void init()
    {
        super.init();
        updateOwncloudAcct();
    }


    /* (non-Javadoc)
     * @see com.jefftharris.passwdsafe.sync.lib.Provider#startAccountLink(android.app.Activity, int)
     */
    @Override
    public void startAccountLink(FragmentActivity activity, int requestCode)
    {
        AccountChooserDlg dialog = AccountChooserDlg.newInstance(
                SyncDb.OWNCLOUD_ACCOUNT_TYPE, requestCode,
                activity.getString(R.string.no_owncloud_accts));
        dialog.show(activity.getSupportFragmentManager(), null);
    }

    /* (non-Javadoc)
     * @see com.jefftharris.passwdsafe.sync.lib.Provider#finishAccountLink(int, android.content.Intent, android.net.Uri)
     */
    @Override
    public NewAccountTask finishAccountLink(int activityResult,
                                            Intent activityData,
                                            Uri providerAcctUri)
    {
        String accountName = null;
        do {
            if ((activityResult != Activity.RESULT_OK) ||
                    (activityData == null)) {
                break;
            }

            Bundle b = activityData.getExtras();
            accountName = b.getString(AccountManager.KEY_ACCOUNT_NAME);
            Log.i(TAG, "Selected account: " + accountName);
            if (TextUtils.isEmpty(accountName)) {
                accountName = null;
                break;
            }
        } while(false);

        saveAuthData(accountName, createUrlFromAccount(accountName, true));
        updateOwncloudAcct();

        if (accountName == null) {
            return null;
        }
        return new NewAccountTask(providerAcctUri, accountName,
                                  ProviderType.OWNCLOUD, true, getContext())
        {
            @Override
            protected void doAccountUpdate(ContentResolver cr)
            {
                Activity act = getActivity();
                String authToken =
                        getAuthToken(getAccount(itsNewAcct), act, act);
                if (authToken != null) {
                    super.doAccountUpdate(cr);
                }
            }
        };
    }

    /* (non-Javadoc)
     * @see com.jefftharris.passwdsafe.sync.lib.Provider#unlinkAccount()
     */
    @Override
    public void unlinkAccount()
    {
        saveCertAlias(null, getContext());
        saveAuthData(null, null);
        updateOwncloudAcct();
        AccountManager acctMgr = AccountManager.get(getContext());
        acctMgr.invalidateAuthToken(
                SyncDb.OWNCLOUD_ACCOUNT_TYPE,
                AccountTypeUtils.getAuthTokenTypePass(
                        SyncDb.OWNCLOUD_ACCOUNT_TYPE));
    }

    /* (non-Javadoc)
     * @see com.jefftharris.passwdsafe.sync.lib.Provider#isAccountAuthorized()
     */
    @Override
    public boolean isAccountAuthorized()
    {
        return (itsAccountName != null) && !itsIsSyncAuthError;
    }

    /* (non-Javadoc)
     * @see com.jefftharris.passwdsafe.sync.lib.Provider#getAccount(java.lang.String)
     */
    @Override
    public Account getAccount(String acctName)
    {
        return new Account(acctName, SyncDb.OWNCLOUD_ACCOUNT_TYPE);
    }

    /* (non-Javadoc)
     * @see com.jefftharris.passwdsafe.sync.lib.Provider#checkProviderAdd(android.database.sqlite.SQLiteDatabase)
     */
    @Override
    public void checkProviderAdd(SQLiteDatabase db) throws Exception
    {
        List<DbProvider> providers = SyncDb.getProviders(db);
        for (DbProvider provider: providers) {
            if (provider.itsType == ProviderType.OWNCLOUD) {
                throw new Exception("Only one ownCloud account allowed");
            }
        }
    }

    /* (non-Javadoc)
     * @see com.jefftharris.passwdsafe.sync.lib.Provider#cleanupOnDelete(java.lang.String)
     */
    @Override
    public void cleanupOnDelete(String acctName) throws Exception
    {
        unlinkAccount();
    }

    /* (non-Javadoc)
     * @see com.jefftharris.passwdsafe.sync.lib.Provider#requestSync(boolean)
     */
    @Override
    public void requestSync(boolean manual)
    {
        PasswdSafeUtil.dbginfo(TAG, "requestSync client: %b", itsAccountName);
        if (itsAccountName == null) {
            return;
        }
        doRequestSync(manual);
    }

    @Override
    public SyncConnectivityResult checkSyncConnectivity(Account acct)
            throws Exception
    {
        final ObjectHolder<SyncConnectivityResult> connResult =
                new ObjectHolder<>();
        useOwncloudService(new OwncloudUser()
        {
            @Override
            public void useOwncloud(OwnCloudClient client) throws Exception
            {
                String displayName =
                        OwncloudSyncer.getDisplayName(client, getContext());
                connResult.set(new SyncConnectivityResult(displayName));
            }
        });
        return connResult.get();
    }

    /* (non-Javadoc)
     * @see com.jefftharris.passwdsafe.sync.lib.Provider#sync(android.accounts.Account, com.jefftharris.passwdsafe.sync.lib.DbProvider, android.database.sqlite.SQLiteDatabase, boolean, boolean, com.jefftharris.passwdsafe.sync.lib.SyncLogRecord)
     */
    @Override
    public void sync(Account acct,
                     final DbProvider provider,
                     final SyncConnectivityResult connResult,
                     final SyncLogRecord logrec) throws Exception
    {
        useOwncloudService(new OwncloudUser()
        {
            @Override
            public void useOwncloud(OwnCloudClient client) throws Exception
            {
                PasswdSafeUtil.dbginfo(TAG, "sync client: %b", itsAccountName);
                OwncloudSyncer syncer =
                        new OwncloudSyncer(client, provider, connResult,
                                           logrec, getContext());
                try {
                    syncer.sync();
                } catch (SyncIOException e) {
                    if (e.isRetry()) {
                        requestSync(false);
                    }
                    throw e;
                } finally {
                    itsIsSyncAuthError = !syncer.isAuthorized();
                }
            }
        });
    }


    /** Create a ownCloud client to a server */
    public final OwnCloudClient getClient(Context ctx)
    {
        Account account = getAccount(itsAccountName);

        OwnCloudClient client = OwnCloudClientFactory.createOwnCloudClient(
                itsUrl, ctx, true);
        client.setFollowRedirects(true);

        client.clearCredentials();
        String authToken = getAuthToken(account, ctx, null);
        if (authToken != null) {
            client.setCredentials(
                    OwnCloudCredentialsFactory.newBasicCredentials(
                            itsUserName, authToken));
        }
        return client;
    }


    /** Get the ownCloud URL */
    public final Uri getUrl()
    {
        return itsUrl;
    }


    /** Set account settings */
    public final void setSettings(String url)
    {
        // TODO: test deadlock with this update and gdrive on startup
        if (!TextUtils.equals(itsUrl.toString(), url)) {
            saveAuthData(itsAccountName, url);
            updateOwncloudAcct();
        }
    }


    /* (non-Javadoc)
     * @see com.jefftharris.passwdsafe.sync.lib.AbstractSyncTimerProvider#getAccountUserId()
     */
    @Override
    protected String getAccountUserId()
    {
        return itsAccountName;
    }

    /**
     * Interface for users of the ownCloud service
     */
    private interface OwncloudUser
    {
        /**
         * Callback to user the service
         */
        void useOwncloud(OwnCloudClient client) throws Exception;
    }

    /**
     * Use the ownCloud service
     */
    private void useOwncloudService(OwncloudUser user) throws Exception
    {
        if (itsAccountName == null) {
            return;
        }
        user.useOwncloud(getClient(getContext()));
    }

    /** Update the ownCloud account client based on availability of
     *  authentication information. */
    private synchronized void updateOwncloudAcct()
    {
        SharedPreferences prefs =
                PreferenceManager.getDefaultSharedPreferences(getContext());

        itsAccountName = prefs.getString(PREF_AUTH_ACCOUNT, null);
        String urlStr = prefs.getString(PREF_URL, null);
        PasswdSafeUtil.dbginfo(TAG, "updateOwncloudAcct token %b, url %s",
                               itsAccountName, urlStr);

        String userName = null;
        Uri url = null;

        if (itsAccountName != null) {
            int pos = itsAccountName.indexOf('@');
            if (pos != -1) {
                userName = itsAccountName.substring(0, pos);

                // Check upgrade
                if ((urlStr == null) && prefs.contains(PREF_USE_HTTPS)) {
                    boolean useHttps = prefs.getBoolean(PREF_USE_HTTPS, true);
                    urlStr = createUrlFromAccount(itsAccountName, useHttps);

                    SharedPreferences.Editor editor = prefs.edit();
                    editor.remove(PREF_USE_HTTPS);
                    editor.putString(PREF_URL, urlStr);
                    editor.apply();
                }

                if (urlStr != null) {
                    url = Uri.parse(urlStr);
                }
            } else {
                itsAccountName = null;
            }
        }

        itsUserName = userName;
        itsUrl = url;
        if (itsUrl != null) {
            try {
                updateProviderSyncFreq(itsAccountName);
                requestSync(false);
            } catch (Exception e) {
                Log.e(TAG, "updateOwncloudAcct failure", e);
            }
        } else {
            updateSyncFreq(null, 0);
        }
    }

    /**
     * Create the ownCloud URL from the account name
     */
    private static String createUrlFromAccount(String accountName,
                                               boolean useHttps)
    {
        if (accountName == null) {
            return null;
        }
        int pos = accountName.indexOf('@');
        if (pos == -1) {
            return null;
        }
        Uri.Builder builder = new Uri.Builder();
        builder.scheme(useHttps ? "https" : "http");
        builder.authority(accountName.substring(pos + 1));
        builder.path("/owncloud");
        return builder.build().toString();
    }

    /** Save or clear the ownCloud authentication data */
    private void saveAuthData(String accountName, String url)
    {
        synchronized (OwncloudProvider.class) {
            PasswdSafeUtil.dbginfo(TAG, "saveAuthData: %b", accountName);
            SharedPreferences prefs =
                    PreferenceManager.getDefaultSharedPreferences(getContext());
            SharedPreferences.Editor editor = prefs.edit();
            if (accountName != null) {
                editor.putString(PREF_AUTH_ACCOUNT, accountName);
                editor.putString(PREF_URL, url);
            } else {
                editor.remove(PREF_AUTH_ACCOUNT);
                editor.remove(PREF_URL);
                editor.remove(PREF_USE_HTTPS);
            }
            editor.apply();
        }
    }


    /** Save or clear the ownCloud SSL certificate */
    public static void saveCertAlias(String certAlias, Context ctx)
    {
        synchronized (OwncloudProvider.class) {
            PasswdSafeUtil.dbginfo(TAG, "saveCertAlias: %s", certAlias);
            SharedPreferences prefs =
                    PreferenceManager.getDefaultSharedPreferences(ctx);
            SharedPreferences.Editor editor = prefs.edit();
            if (certAlias != null) {
                editor.putString(PREF_CERT_ALIAS, certAlias);
            } else {
                String currAlias = prefs.getString(PREF_CERT_ALIAS, null);
                if (currAlias != null) {
                    try {
                        NetworkUtils.removeCertFromKnownServersStore(currAlias,
                                                                     ctx);
                    } catch (Exception e) {
                        Log.e(TAG, "Error clearing certificate: " + currAlias,
                              e);
                    }
                }
                editor.remove(PREF_CERT_ALIAS);
            }
            editor.apply();
        }
    }


    /**
     * Get the ownCloud authentication for an account. A notification may be
     * presented if authorization is required. Must be called from a background
     * thread.
     */
    @SuppressWarnings("deprecation")
    private static String getAuthToken(Account account,
                                       Context ctx,
                                       Activity activity)
    {
        String authToken = null;
        try {
            AccountManager acctMgr = AccountManager.get(ctx);
            String authType = AccountTypeUtils.getAuthTokenTypePass(
                    SyncDb.OWNCLOUD_ACCOUNT_TYPE);
            AccountManagerFuture<Bundle> fut;
            if ((activity != null) &&
                    ApiCompat.canAccountMgrGetAuthTokenWithDialog()) {
                fut = acctMgr.getAuthToken(account, authType, null,
                                           activity, null, null);
            } else {
                fut = acctMgr.getAuthToken(account, authType, true, null, null);
            }
            Bundle b = fut.getResult(60, TimeUnit.SECONDS);
            authToken = b.getString(AccountManager.KEY_AUTHTOKEN);
        } catch (Throwable e) {
            PasswdSafeUtil.dbginfo(TAG, e, "getAuthToken");
        }

        PasswdSafeUtil.dbginfo(TAG, "getAuthToken: %b", (authToken != null));
        return authToken;
    }
}

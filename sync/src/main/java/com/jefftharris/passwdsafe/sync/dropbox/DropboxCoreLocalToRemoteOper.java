/*
 * Copyright (©) 2016 Jeff Harris <jefftharris@gmail.com>
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */
package com.jefftharris.passwdsafe.sync.dropbox;

import android.content.Context;
import android.util.Log;

import com.dropbox.core.DbxException;
import com.dropbox.core.v2.DbxClientV2;
import com.dropbox.core.v2.files.FileMetadata;
import com.dropbox.core.v2.files.WriteMode;
import com.jefftharris.passwdsafe.lib.PasswdSafeUtil;
import com.jefftharris.passwdsafe.lib.Utils;
import com.jefftharris.passwdsafe.sync.lib.AbstractLocalToRemoteSyncOper;
import com.jefftharris.passwdsafe.sync.lib.DbFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Date;

/**
 * A Dropbox sync operation to sync a local file to a remote one
 */
public class DropboxCoreLocalToRemoteOper
        extends AbstractLocalToRemoteSyncOper<DbxClientV2>
{
    private static final String TAG = "DropboxCoreLocalToRemot";

    /** Constructor */
    public DropboxCoreLocalToRemoteOper(DbFile dbfile)
    {
        super(dbfile, TAG);
    }

    /** Perform the sync operation */
    @Override
    public void doOper(DbxClientV2 providerClient,
                       Context ctx) throws DbxException, IOException
    {
        PasswdSafeUtil.dbginfo(TAG, "syncLocalToRemote %s", itsFile);

        File tmpFile = null;
        FileInputStream fis = null;
        try {
            File uploadFile;
            String remotePath;
            if (itsFile.itsLocalFile != null) {
                uploadFile = ctx.getFileStreamPath(itsFile.itsLocalFile);
                setLocalFile(uploadFile);
                if (isInsert()) {
                    remotePath =
                            DropboxCoreSyncer.createRemoteIdFromLocal(itsFile);
                } else {
                    remotePath = itsFile.itsRemoteId;
                }
            } else {
                tmpFile = File.createTempFile("passwd", ".psafe3");
                tmpFile.deleteOnExit();
                uploadFile = tmpFile;
                remotePath = DropboxCoreSyncer.createRemoteIdFromLocal(itsFile);
            }

            fis = new FileInputStream(uploadFile);
            FileMetadata updatedEntry =
                    providerClient.files().uploadBuilder(remotePath)
                    .withMode(WriteMode.OVERWRITE)
                    .withClientModified(new Date(itsFile.itsLocalModDate))
                    .uploadAndFinish(fis);

            setUpdatedFile(new DropboxCoreProviderFile(updatedEntry));
        } finally {
            Utils.closeStreams(fis);
            if ((tmpFile != null) && !tmpFile.delete()) {
                Log.e(TAG, "Can't delete temp file " + tmpFile);
            }
        }
    }
}

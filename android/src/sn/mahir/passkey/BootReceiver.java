package sn.mahir.passkey;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Restarts the service after boot and after an app update. */
public class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent i) {
        KeyService.start(c);
    }
}

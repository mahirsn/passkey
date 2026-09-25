package sn.mahir.passkey;

import android.app.Activity;
import android.app.KeyguardManager;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.SystemClock;

/** One confirmation: fingerprint (or the device PIN). Reports to KeyService and
 *  closes. Closed without an answer (back), the request stays open: the
 *  notification opens the prompt again, or rejects it. */
public class PromptActivity extends Activity {
    private CancellationSignal cancel = new CancellationSignal();
    private boolean started, reported, unlocking;
    private long id, startedAt;
    private int quickCancels;       // in a row, over the lock screen

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        setShowWhenLocked(true);
        setTurnScreenOn(true);
        id = getIntent().getLongExtra("id", -1);
        if (!KeyService.attach(id, this)) finish();
    }

    // Over the lock screen the activity is briefly "asleep" and a prompt started
    // then is cancelled at once, so start on window focus. If the system cancels
    // it (screen turned off, ...), try again on the next focus.
    @Override public void onWindowFocusChanged(boolean focus) {
        super.onWindowFocusChanged(focus);
        if (focus && !started && !reported) authenticate();
    }

    // Some devices (a Galaxy Tab) let the prompt use the sensor over the lock
    // screen, so one touch approves while the device stays locked. On others
    // (a Mi 9T) the lock screen keeps the sensor and cancels the prompt at
    // once, every time; those unlock first, and the device remembers it.
    private boolean unlockFirst() {
        return getSharedPreferences("prompt", MODE_PRIVATE).getBoolean("unlock_first", false);
    }

    private void authenticate() {
        started = true;
        KeyguardManager km = getSystemService(KeyguardManager.class);
        if (km.isKeyguardLocked() && (unlockFirst() || quickCancels >= 2)) {
            // Unlock, then the prompt. The unlock alone never counts as approval:
            // it does not say what is being approved, and face unlock or Smart
            // Lock may not be strong.
            if (unlocking) return;
            unlocking = true;
            km.requestDismissKeyguard(this, new KeyguardManager.KeyguardDismissCallback() {
                @Override public void onDismissSucceeded() {
                    unlocking = false;
                    started = false;
                    if (hasWindowFocus()) authenticate();
                }
                @Override public void onDismissCancelled() { unlocking = false; finish(); }
                @Override public void onDismissError() { unlocking = false; finish(); }
            });
            return;
        }
        cancel = new CancellationSignal();
        startedAt = SystemClock.elapsedRealtime();
        new BiometricPrompt.Builder(this)
                .setTitle(getIntent().getStringExtra("title"))
                .setSubtitle(getIntent().getStringExtra("detail"))
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
                        | BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build()
                .authenticate(cancel, getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                    @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) {
                        report(Authenticator.OK);
                    }
                    @Override public void onAuthenticationError(int code, CharSequence msg) {
                        if (code == BiometricPrompt.BIOMETRIC_ERROR_CANCELED && !reported) {
                            started = false;          // the system cut it short, not the user
                            boolean quick = SystemClock.elapsedRealtime() - startedAt < 500;
                            quickCancels = quick && km.isKeyguardLocked() ? quickCancels + 1 : 0;
                            if (quickCancels == 2) {  // the lock screen has the sensor
                                getSharedPreferences("prompt", MODE_PRIVATE).edit()
                                        .putBoolean("unlock_first", true).apply();
                                if (hasWindowFocus()) authenticate();
                            }
                            return;
                        }
                        if (code == BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT && !reported) {
                            started = false;          // the sensor's own time ran out; ask again
                            if (hasWindowFocus()) authenticate();
                            return;
                        }
                        if (code == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED) {
                            finish();                 // closed, not refused
                            return;
                        }
                        report(Authenticator.ERR_OPERATION_DENIED);
                    }
                });
    }

    /** The computer gave up, or the time ran out. */
    void abort() {
        reported = true;
        cancel.cancel();
        finish();
    }

    private void report(int status) {
        if (!reported) { reported = true; KeyService.answer(id, status); }
        finish();
    }

    @Override protected void onDestroy() {
        if (!reported) KeyService.detach(id, this);
        super.onDestroy();
    }
}

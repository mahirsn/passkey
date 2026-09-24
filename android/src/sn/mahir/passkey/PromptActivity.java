package sn.mahir.passkey;

import android.app.Activity;
import android.app.KeyguardManager;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Bundle;
import android.os.CancellationSignal;

/** One confirmation: fingerprint (or the device PIN). Reports to KeyService and closes. */
public class PromptActivity extends Activity {
    private CancellationSignal cancel = new CancellationSignal();
    private boolean started, reported, unlocking;
    private long id;

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

    private void authenticate() {
        started = true;
        KeyguardManager km = getSystemService(KeyguardManager.class);
        if (km.isKeyguardLocked()) {
            // The lock screen owns the fingerprint sensor, so unlock first. The
            // unlock alone never counts as approval: it does not say what is being
            // approved, and face unlock or Smart Lock may not be strong.
            if (unlocking) return;
            unlocking = true;
            km.requestDismissKeyguard(this, new KeyguardManager.KeyguardDismissCallback() {
                @Override public void onDismissSucceeded() {
                    unlocking = false;
                    started = false;
                    if (hasWindowFocus()) authenticate();
                }
                @Override public void onDismissCancelled() { unlocking = false; report(Authenticator.ERR_OPERATION_DENIED); }
                @Override public void onDismissError() { unlocking = false; report(Authenticator.ERR_OPERATION_DENIED); }
            });
            return;
        }
        cancel = new CancellationSignal();
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
        report(Authenticator.ERR_OPERATION_DENIED);
        super.onDestroy();
    }
}

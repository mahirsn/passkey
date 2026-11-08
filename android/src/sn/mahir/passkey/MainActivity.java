package sn.mahir.passkey;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;


/** Status and the few permissions the app needs. */
public class MainActivity extends Activity {
    private static final String COMPANION_URL = "https://github.com/mahirsn/passkey";
    private static final int BACKGROUND = 0xFF141516;

    private final Handler h = new Handler(Looper.getMainLooper());
    private LinearLayout root;
    private String lastRender = "";
    private int accent, onAccent, surface, text, muted, good;

    @SuppressWarnings("deprecation")    // only used before Android 15, where it is not
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        palette();
        if (getActionBar() != null) getActionBar().hide();
        // Edge to edge; from Android 15 on it is always so.
        if (Build.VERSION.SDK_INT < 35) getWindow().setDecorFitsSystemWindows(false);

        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(BACKGROUND);
        sv.setClipToPadding(false);
        sv.addView(root);
        int side = dp(20);
        sv.setOnApplyWindowInsetsListener((v, in) -> {
            android.graphics.Insets i = in.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            v.setPadding(side + i.left, dp(12) + i.top, side + i.right, dp(24) + i.bottom);
            return WindowInsets.CONSUMED;
        });
        setContentView(sv);
        KeyService.start(this);
    }

    private void palette() {
        // Always dark, on the brand background; the accent follows the wallpaper.
        if (Build.VERSION.SDK_INT >= 31) {
            accent = getColor(android.R.color.system_accent1_200);
            onAccent = getColor(android.R.color.system_accent1_800);
        } else {
            accent = 0xFFA8C7FA;
            onAccent = 0xFF0B2A6B;
        }
        surface = 0xFF1F2123;
        text = 0xFFE6E7E9;
        muted = 0xFFA3A6AB;
        good = 0xFF7DD99A;
    }

    @Override protected void onResume() {
        super.onResume();
        lastRender = "";
        tick();
    }

    @Override protected void onPause() {
        h.removeCallbacksAndMessages(null);
        super.onPause();
    }

    private void tick() {
        render();
        h.postDelayed(this::tick, 1000);
    }

    // --- screen ----------------------------------------------------------------------
    private void render() {
        boolean bt = Build.VERSION.SDK_INT < 31 || granted(Manifest.permission.BLUETOOTH_CONNECT);
        boolean notif = Build.VERSION.SDK_INT < 33 || granted(Manifest.permission.POST_NOTIFICATIONS);
        boolean overlay = Settings.canDrawOverlays(this);
        boolean battery = getSystemService(PowerManager.class).isIgnoringBatteryOptimizations(getPackageName());
        String link = KeyService.link;
        boolean wifi = WifiTransport.enabled(this);
        String wifiState = KeyService.running != null && KeyService.running.wifi != null ? KeyService.running.wifi.status : "Starting…";
        String wifiAddresses = String.join(", ", WifiTransport.addresses(this));

        StringBuilder key = new StringBuilder(String.valueOf(link));
        key.append(bt).append(notif).append(overlay).append(battery).append(wifi).append(wifiState).append(wifiAddresses);
        if (key.toString().equals(lastRender)) return;
        lastRender = key.toString();
        root.removeAllViews();

        TextView title = label("Passkey", 30, text, true);
        title.setPadding(dp(4), dp(8), 0, dp(4));
        root.addView(title);
        TextView tag = label("Your fingerprint, as a security key for your computer.", 15, muted, false);
        tag.setPadding(dp(4), 0, 0, dp(16));
        root.addView(tag);

        // Connection
        LinearLayout c = card();
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        View dot = new View(this);
        GradientDrawable dd = new GradientDrawable();
        dd.setShape(GradientDrawable.OVAL);
        dd.setColor(link != null ? good : muted);
        dot.setBackground(dd);
        row.addView(dot, new LinearLayout.LayoutParams(dp(12), dp(12)));
        TextView st = label(link != null ? "Connected" : "Not connected", 20, text, true);
        st.setPadding(dp(12), 0, 0, 0);
        row.addView(st);
        c.addView(row);
        c.addView(body(link != null ? link
                : "Connect over paired Wi-Fi, plug in a USB cable or keep Bluetooth on near your computer. "
                  + "The connection is picked up automatically."));
        root.addView(c);

        LinearLayout wifiCard = card();
        wifiCard.addView(heading("Local Wi-Fi"));
        wifiCard.addView(body(wifi ? wifiState + (wifiAddresses.isEmpty() ? " — connect to Wi-Fi first." : " — " + wifiAddresses + ":" + WifiTransport.PORT)
                : "Connect directly on the same Wi-Fi. USB debugging and Bluetooth are not required."));
        wifiCard.addView(button(wifi ? "Turn Wi-Fi off" : "Enable Wi-Fi", true, v -> {
            getSharedPreferences("wifi", MODE_PRIVATE).edit().putBoolean("enabled", !wifi).apply();
            if (KeyService.running != null && KeyService.running.wifi != null) {
                if (wifi) KeyService.running.wifi.disable(); else KeyService.running.wifi.start();
            }
            lastRender = ""; render();
        }));
        if (wifi) {
            wifiCard.addView(body("On your computer: passkey wifi add <phone IP>, paste the pairing code when asked, then run passkey add."));
            wifiCard.addView(button("Copy pairing code", false, v -> {
                try {
                    if (KeyService.running == null || KeyService.running.wifi == null) return;
                    android.content.ClipData clip = android.content.ClipData.newPlainText("Passkey Wi-Fi pairing", KeyService.running.wifi.pairingCode());
                    if (Build.VERSION.SDK_INT >= 33) {
                        android.os.PersistableBundle extras = new android.os.PersistableBundle();
                        extras.putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, true);
                        clip.getDescription().setExtras(extras);
                    }
                    getSystemService(android.content.ClipboardManager.class).setPrimaryClip(clip);
                    android.widget.Toast.makeText(this, "Pairing code copied. Keep it private.", android.widget.Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    android.widget.Toast.makeText(this, "Could not create pairing code", android.widget.Toast.LENGTH_LONG).show();
                }
            }));
            wifiCard.addView(button("Forget all Wi-Fi computers", false, v -> new android.app.AlertDialog.Builder(this)
                    .setTitle("Reset Wi-Fi pairing?").setMessage("Connected Wi-Fi computers will be disconnected and must pair again.")
                    .setNegativeButton("Cancel", null).setPositiveButton("Reset", (dialog, which) -> {
                        try { if (KeyService.running != null) KeyService.running.wifi.reset(); }
                        catch (java.io.IOException e) { android.widget.Toast.makeText(this, "Could not reset pairing", android.widget.Toast.LENGTH_LONG).show(); }
                    }).show()));
        }
        root.addView(wifiCard);

        // Setup
        boolean ready = notif;
        if (!ready || !bt || !overlay || !battery) {
            LinearLayout s = card();
            s.addView(heading("Setup"));
            if (!notif) step(s, "Notifications", "Required to ask for your fingerprint.",
                    "Allow", v -> requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1));
            if (!bt) step(s, "Bluetooth (optional)", "Needed only to connect over Bluetooth.",
                    "Allow", v -> requestPermissions(new String[]{Manifest.permission.BLUETOOTH_CONNECT}, 1));
            if (!overlay) step(s, "Show prompts instantly (optional)",
                    "Lets the fingerprint prompt open by itself. Without it, tap the notification.",
                    "Open settings", v -> startActivity(new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                            Uri.parse("package:" + getPackageName()))));
            if (!battery) step(s, "Stay connected (optional)",
                    "Set battery usage to Unrestricted so the connection is not cut while the screen is off.",
                    "Open settings", v -> startActivity(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)));
            root.addView(s);
        }

        // Computer
        LinearLayout pc = card();
        pc.addView(heading("On your computer"));
        pc.addView(body("Linux: install the companion, then run \"passkey add\". "
                + "It adds your fingerprint to login, the lock screen, sudo and system prompts, "
                + "and makes it work as a passkey in your browser."));
        pc.addView(body("For Bluetooth, pair this device with the computer once in Bluetooth settings."));
        LinearLayout btns = new LinearLayout(this);
        btns.addView(button("Get companion", true, v ->
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(COMPANION_URL)))));
        Button pair = button("Pair Bluetooth", false, v -> {
            if (!bt && Build.VERSION.SDK_INT >= 31) requestPermissions(new String[]{Manifest.permission.BLUETOOTH_CONNECT}, 1);
            else startActivity(new Intent(Settings.ACTION_BLUETOOTH_SETTINGS));
        });
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-2, -2);
        lp.leftMargin = dp(8);
        btns.addView(pair, lp);
        pc.addView(btns);
        root.addView(pc);

    }

    // --- small view helpers ------------------------------------------------------------
    private void step(LinearLayout parent, String t, String d, String action, View.OnClickListener l) {
        LinearLayout s = new LinearLayout(this);
        s.setOrientation(LinearLayout.VERTICAL);
        s.setPadding(0, dp(8), 0, dp(8));
        s.addView(label(t, 16, text, true));
        TextView dv = label(d, 14, muted, false);
        dv.setPadding(0, dp(2), 0, dp(8));
        s.addView(dv);
        s.addView(button(action, true, l), new LinearLayout.LayoutParams(-2, -2));
        parent.addView(s);
    }

    private LinearLayout card() {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.setPadding(dp(20), dp(18), dp(20), dp(18));
        GradientDrawable g = new GradientDrawable();
        g.setColor(surface);
        g.setCornerRadius(dp(24));
        c.setBackground(g);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.bottomMargin = dp(12);
        c.setLayoutParams(lp);
        return c;
    }

    private TextView heading(String s) {
        TextView t = label(s, 18, text, true);
        t.setPadding(0, 0, 0, dp(4));
        return t;
    }

    private TextView body(String s) {
        TextView t = label(s, 15, muted, false);
        t.setPadding(0, dp(6), 0, dp(6));
        t.setLineSpacing(0, 1.15f);
        return t;
    }

    private TextView label(String s, int sp, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        return t;
    }

    private Button button(String s, boolean filled, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(s);
        b.setSingleLine(true);
        b.setAllCaps(false);
        b.setTextColor(filled ? onAccent : accent);
        b.setStateListAnimator(null);
        b.setMinHeight(dp(44));
        b.setPadding(dp(18), 0, dp(18), 0);
        GradientDrawable g = new GradientDrawable();
        g.setCornerRadius(dp(22));
        if (filled) g.setColor(accent); else { g.setColor(Color.TRANSPARENT); g.setStroke(dp(1), accent); }
        b.setBackground(new android.graphics.drawable.RippleDrawable(
                android.content.res.ColorStateList.valueOf(filled ? 0x33FFFFFF : (accent & 0x33FFFFFF)), g, null));
        b.setOnClickListener(l);
        return b;
    }

    private boolean granted(String p) { return checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED; }

    private int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }
}

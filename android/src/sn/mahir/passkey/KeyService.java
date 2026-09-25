package sn.mahir.passkey;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothClass;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothSocket;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.os.IBinder;
import android.util.Log;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Talks to the computer. Two transports, same frames:
 *  - USB: adb connects to the abstract socket "passkey" (only adbd/root may connect).
 *  - Bluetooth: RFCOMM to a paired computer that registered BT_UUID.
 *  Frame: 4-byte big-endian length + body. body[0] is the type; REQ, RESP and
 *  CANCEL then carry a 4-byte request number, so a late answer or a stale
 *  cancel never applies to a newer request. */
public class KeyService extends Service {
    static final UUID BT_UUID = UUID.fromString("7a1b6b65-7900-4e6f-9d2a-6d6168697273");
    static final int REQ = 0x10, CANCEL = 0x11, PING = 0x12, RESP = 0x20, PONG = 0x22;
    // The computer ends a request when its own prompt closes; this only covers
    // a computer that went quiet without saying so.
    static final int PROMPT_TIMEOUT_MS = 10 * 60_000;
    static final String TAG = "passkey";
    static final String ACTION_REJECT = "sn.mahir.passkey.REJECT";

    /** Shown in the app; null when no computer is connected. */
    static volatile String link;
    static volatile KeyService running;

    private Authenticator auth;
    private volatile boolean stop;
    private int connections;

    /** One computer connection. */
    static final class Conn {
        int cancelled = Integer.MIN_VALUE;   // request number the computer withdrew
        boolean closed;
    }

    // Connection and request number of the request on this worker thread.
    private static final ThreadLocal<Conn> caller = new ThreadLocal<>();
    private static final ThreadLocal<Integer> callerSeq = new ThreadLocal<>();

    // --- the prompt (one at a time) -------------------------------------------------
    private static final Object lock = new Object();
    private static long seq;
    private static long current = -1;
    private static Conn owner;
    private static int ownerSeq;
    private static int result;
    private static PromptActivity shown;

    static boolean attach(long id, PromptActivity a) {
        synchronized (lock) {
            if (id != current) return false;
            shown = a;
            return true;
        }
    }

    /** The prompt closed without an answer (back button): the request stays
     *  open and its notification brings the prompt back. */
    static void detach(long id, PromptActivity a) {
        synchronized (lock) {
            if (id == current && shown == a) shown = null;
        }
    }

    static void answer(long id, int status) {
        synchronized (lock) {
            if (id != current) return;
            result = status;
            current = -1;
            lock.notifyAll();
        }
    }

    /** The computer withdrew request `seq`, or (closed) its connection went
     *  away. Only that connection's prompt is closed. */
    static void cancel(Conn c, int seq, boolean closed) {
        synchronized (lock) {
            c.cancelled = seq;
            c.closed |= closed;
            if (current < 0 || owner != c || (!closed && ownerSeq != seq)) return;
            result = Authenticator.ERR_KEEPALIVE_CANCEL;
            current = -1;
            if (shown != null) { PromptActivity a = shown; a.runOnUiThread(a::abort); }
            lock.notifyAll();
        }
    }

    private int confirm(String title, String detail) {
        if (Flags.AUTO_APPROVE) return Authenticator.OK;     // test builds only
        Conn c = caller.get();
        Integer mine = callerSeq.get();
        long id;
        synchronized (lock) {
            // A cancel that arrived before the prompt existed still counts.
            if (c != null && (c.closed || (mine != null && c.cancelled == mine)))
                return Authenticator.ERR_KEEPALIVE_CANCEL;
            id = ++seq;
            current = id;
            owner = c;
            ownerSeq = mine == null ? 0 : mine;
            shown = null;
            result = Authenticator.ERR_USER_ACTION_TIMEOUT;
        }
        Intent i = new Intent(this, PromptActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_NO_ANIMATION
                        | Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS)
                .putExtra("id", id).putExtra("title", title).putExtra("detail", detail);
        // With "display over other apps" the prompt opens by itself; otherwise
        // tapping this notification opens it.
        PendingIntent pi = PendingIntent.getActivity(this, (int) id, i,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.notify(2, new Notification.Builder(this, "prompt")
                .setSmallIcon(R.drawable.ic_notify)
                .setContentTitle(title).setContentText(detail)
                .setContentIntent(pi)
                // Stays until the request ends, so a prompt closed by mistake
                // can be opened again; "Reject" refuses it from here.
                .setOngoing(true)
                .addAction(new Notification.Action.Builder(null, "Reject", PendingIntent.getService(this, (int) id,
                        new Intent(this, KeyService.class).setAction(ACTION_REJECT).putExtra("id", id),
                        PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT)).build())
                .build());
        try { startActivity(i); } catch (Exception e) { Log.w(TAG, "prompt not started", e); }

        int r;
        synchronized (lock) {
            long end = System.currentTimeMillis() + PROMPT_TIMEOUT_MS;
            while (current == id) {
                long left = end - System.currentTimeMillis();
                if (left <= 0) break;
                try { lock.wait(left); } catch (InterruptedException e) { break; }
            }
            if (current == id) {           // timed out
                current = -1;
                if (shown != null) { PromptActivity a = shown; a.runOnUiThread(a::abort); }
            }
            r = result;
            shown = null;
            owner = null;
        }
        nm.cancel(2);
        return r;
    }

    // --- service ---------------------------------------------------------------------
    @Override public void onCreate() {
        super.onCreate();
        running = this;
        auth = new Authenticator(this, this::confirm);
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("run", "Running in background", NotificationManager.IMPORTANCE_MIN));
        nm.createNotificationChannel(new NotificationChannel("prompt", "Sign-in requests", NotificationManager.IMPORTANCE_HIGH));
        Notification n = new Notification.Builder(this, "run")
                .setSmallIcon(R.drawable.ic_notify)
                .setContentTitle("Ready for your computer")
                .setContentIntent(PendingIntent.getActivity(this, 0,
                        new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE))
                .build();
        startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        new Thread(this::localLoop, "tk-usb").start();
        if (!Flags.AUTO_APPROVE) new Thread(this::bluetoothLoop, "tk-bt").start();
    }

    @Override public int onStartCommand(Intent i, int f, int id) {
        if (i != null && ACTION_REJECT.equals(i.getAction()))
            answer(i.getLongExtra("id", -1), Authenticator.ERR_OPERATION_DENIED);
        return START_STICKY;
    }
    @Override public IBinder onBind(Intent i) { return null; }

    @Override public void onDestroy() {
        stop = true;
        running = null;
        super.onDestroy();
    }

    Authenticator authenticator() { return auth; }

    static void start(Context c) {
        c.startForegroundService(new Intent(c, KeyService.class));
    }

    private void localLoop() {
        // Test builds listen elsewhere, so the real companion never reaches one.
        try (LocalServerSocket server = new LocalServerSocket(Flags.AUTO_APPROVE ? "passkey.test" : "passkey")) {
            while (!stop) {
                LocalSocket s = server.accept();
                int uid = s.getPeerCredentials().getUid();
                // Only adbd (shell) and root: another app that finds this socket
                // must not be able to put prompts in front of the user.
                if (uid != 2000 && uid != 0) { s.close(); continue; }
                new Thread(() -> {
                    try { serve("Over USB", s.getInputStream(), s.getOutputStream(), s::close); }
                    catch (IOException e) { Log.w(TAG, "usb", e); }
                }, "tk-usb-conn").start();
            }
        } catch (IOException e) {
            Log.e(TAG, "local socket", e);
        }
    }

    private void bluetoothLoop() {
        BluetoothAdapter ad = getSystemService(BluetoothManager.class).getAdapter();
        while (!stop) {
            try {
                if (ad != null && ad.isEnabled() && checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)
                        == PackageManager.PERMISSION_GRANTED) {
                    for (BluetoothDevice d : ad.getBondedDevices()) {
                        BluetoothClass k = d.getBluetoothClass();
                        if (k == null || k.getMajorDeviceClass() != BluetoothClass.Device.Major.COMPUTER) continue;
                        BluetoothSocket s = d.createRfcommSocketToServiceRecord(BT_UUID);
                        try {
                            s.connect();
                        } catch (IOException e) {
                            try { s.close(); } catch (IOException ignored) {}
                            continue;
                        }
                        serve("To " + d.getName() + " over Bluetooth",
                                s.getInputStream(), s.getOutputStream(), s::close);
                    }
                }
            } catch (SecurityException | IOException e) {
                Log.w(TAG, "bluetooth", e);
            }
            try { Thread.sleep(15_000); } catch (InterruptedException e) { return; }
        }
    }

    interface Closer { void close() throws IOException; }

    /** Runs one connection until it closes. */
    private void serve(String name, InputStream is, OutputStream os, Closer closer) {
        Conn conn = new Conn();
        synchronized (this) { connections++; link = name; }
        DataInputStream in = new DataInputStream(is);
        DataOutputStream out = new DataOutputStream(os);
        // CTAP requests run on their own thread so the reader still sees CANCEL.
        ExecutorService worker = Executors.newSingleThreadExecutor();
        try {
            while (!stop) {
                int n = in.readInt();
                if (n < 1 || n > 8192) throw new IOException("frame length " + n);
                byte[] body = new byte[n];
                in.readFully(body);
                int type = body[0] & 0xFF;
                if (type == PING) {
                    send(out, new byte[]{(byte) PONG});
                } else if (type == CANCEL && n >= 5) {
                    cancel(conn, java.nio.ByteBuffer.wrap(body, 1, 4).getInt(), false);
                } else if (type == REQ && n >= 5) {
                    byte[] seqNo = Arrays.copyOfRange(body, 1, 5);
                    int reqSeq = java.nio.ByteBuffer.wrap(seqNo).getInt();
                    byte[] req = Arrays.copyOfRange(body, 5, n);
                    worker.execute(() -> {
                        caller.set(conn);
                        callerSeq.set(reqSeq);
                        byte[] r = auth.handle(req, conn);
                        byte[] f = new byte[r.length + 5];
                        f[0] = (byte) RESP;
                        System.arraycopy(seqNo, 0, f, 1, 4);
                        System.arraycopy(r, 0, f, 5, r.length);
                        try { send(out, f); } catch (IOException ignored) {}
                    });
                }
            }
        } catch (IOException e) {
            Log.i(TAG, name + " closed: " + e.getMessage());
        } finally {
            cancel(conn, 0, true);
            worker.shutdownNow();
            try { closer.close(); } catch (IOException ignored) {}
            synchronized (this) { if (--connections == 0) link = null; }
        }
    }

    private static void send(DataOutputStream out, byte[] f) throws IOException {
        synchronized (out) {
            out.writeInt(f.length);
            out.write(f);
            out.flush();
        }
    }
}

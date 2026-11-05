package sn.mahir.passkey;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyInfo;
import android.util.Log;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Set;
import java.util.HashSet;
import java.util.concurrent.Semaphore;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.security.auth.x500.X500Principal;

/** TLS on the Wi-Fi interface only; a pinned certificate and a random pairing secret. */
final class WifiTransport {
    static final int PORT = 40719;
    private static final String ALIAS = "passkey.wifi.transport";
    private static final byte[] MAGIC = "PASSKEY-WIFI-1\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private final KeyService service;
    private final SharedPreferences prefs;
    private final Set<SSLSocket> sockets = new HashSet<>();
    private final Semaphore slots = new Semaphore(4);
    private volatile SSLServerSocket server;
    private volatile boolean stopped;
    private byte[] secret;
    private X509Certificate certificate;
    private SSLContext tls;
    volatile String status = "Wi-Fi is off";

    WifiTransport(KeyService service) { this.service = service; prefs = service.getSharedPreferences("wifi", Context.MODE_PRIVATE); }
    static boolean enabled(Context c) { return c.getSharedPreferences("wifi", Context.MODE_PRIVATE).getBoolean("enabled", false); }

    private synchronized void identity() throws Exception {
        if (tls != null) return;
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (store.containsAlias(ALIAS)) {
            PrivateKey existing = (PrivateKey) store.getKey(ALIAS, null);
            KeyInfo info = KeyFactory.getInstance(existing.getAlgorithm(), "AndroidKeyStore").getKeySpec(existing, KeyInfo.class);
            // Conscrypt signs the TLS digest with NONEwithECDSA, not SHA256withECDSA.
            if (!Arrays.asList(info.getDigests()).contains(KeyProperties.DIGEST_NONE)) store.deleteEntry(ALIAS);
        }
        if (!store.containsAlias(ALIAS)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                    .setCertificateSubject(new X500Principal("CN=passkey.wifi"))
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setCertificateNotBefore(new Date(System.currentTimeMillis() - 86400_000L))
                    .setCertificateNotAfter(new Date(System.currentTimeMillis() + 10L * 365 * 86400_000L)).build());
            generator.generateKeyPair();
        }
        certificate = (X509Certificate) store.getCertificate(ALIAS);
        PrivateKey key = (PrivateKey) store.getKey(ALIAS, null);
        String saved = prefs.getString("secret", null);
        if (saved == null) {
            secret = new byte[32]; new SecureRandom().nextBytes(secret);
            if (!prefs.edit().putString("secret", hex(secret)).commit()) throw new IOException("Could not save Wi-Fi pairing");
        } else {
            secret = new byte[32];
            for (int i = 0; i < secret.length; i++) secret[i] = (byte) Integer.parseInt(saved.substring(i * 2, i * 2 + 2), 16);
        }
        WifiKeyManager manager = new WifiKeyManager(ALIAS, key, certificate);
        tls = SSLContext.getInstance("TLS");
        tls.init(new KeyManager[]{manager}, null, new SecureRandom());
    }

    synchronized String pairingCode() throws Exception {
        identity();
        return "pk1:" + hex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded())) + ":" + hex(secret);
    }

    synchronized void start() {
        if (Flags.AUTO_APPROVE || !enabled(service) || stopped || server != null) return;
        // Set the listener synchronously so repeated UI actions cannot start two listeners.
        try {
            identity();
            server = (SSLServerSocket) tls.getServerSocketFactory().createServerSocket(PORT, 4, InetAddress.getByName("0.0.0.0"));
            server.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
            status = "Ready on Wi-Fi";
            SSLServerSocket listener = server;
            new Thread(() -> listen(listener), "passkey-wifi").start();
        } catch (Exception e) {
            disable();
            status = "Wi-Fi could not start: " + e.getMessage();
            Log.w(KeyService.TAG, "wifi listener", e);
        }
    }

    private void listen(SSLServerSocket listener) {
        while (!stopped && !listener.isClosed()) {
            try {
                SSLSocket socket = (SSLSocket) listener.accept();
                // A wildcard bind must never expose the authenticator through mobile data/VPN.
                if (!addresses(service).contains(socket.getLocalAddress().getHostAddress())) {
                    status = "Connection rejected: not on the Wi-Fi interface";
                    socket.close(); continue;
                }
                if (!slots.tryAcquire()) { socket.close(); continue; }
                synchronized (sockets) { sockets.add(socket); }
                new Thread(() -> {
                    boolean handshaken = false;
                    try {
                        socket.setSoTimeout(5000);
                        socket.startHandshake();
                        handshaken = true;
                        status = "Ready on Wi-Fi";
                        DataInputStream input = new DataInputStream(socket.getInputStream());
                        byte[] magic = new byte[MAGIC.length], received = new byte[32];
                        input.readFully(magic); input.readFully(received);
                        byte[] expected;
                        synchronized (this) { expected = secret.clone(); }
                        if (!Arrays.equals(magic, MAGIC) || !MessageDigest.isEqual(received, expected)) throw new IOException("Wi-Fi peer not paired");
                        DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                        output.writeInt(1); output.writeByte(KeyService.PONG);
                        byte[] label = Build.MODEL.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        if (label.length == 0 || label.length > 256) label = "Android phone".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        output.writeShort(label.length); output.write(label); output.flush();
                        socket.setSoTimeout(0);
                        service.serve("Over Wi-Fi", input, output, socket::close);
                    } catch (Exception e) {
                        if (!handshaken && !socket.isClosed()) status = "Wi-Fi TLS error: " + e.getClass().getSimpleName();
                        Log.w(KeyService.TAG, "wifi connection closed", e);
                    } finally {
                        try { socket.close(); } catch (IOException ignored) {}
                        synchronized (sockets) { sockets.remove(socket); }
                        slots.release();
                    }
                }, "passkey-wifi-connection").start();
            } catch (IOException e) {
                if (!listener.isClosed()) { status = "Wi-Fi disconnected"; Log.w(KeyService.TAG, "wifi accept", e); }
                break;
            }
        }
    }

    synchronized void disable() {
        if (server != null) { try { server.close(); } catch (IOException ignored) {} server = null; }
        synchronized (sockets) { for (SSLSocket socket : sockets) { try { socket.close(); } catch (IOException ignored) {} } }
        status = "Wi-Fi is off";
    }
    synchronized void reset() throws IOException {
        disable();
        byte[] next = new byte[32]; new SecureRandom().nextBytes(next);
        if (!prefs.edit().putString("secret", hex(next)).commit()) throw new IOException("Could not reset pairing");
        secret = next;
        start();
    }
    void stop() { stopped = true; disable(); }

    static Set<String> addresses(Context context) {
        Set<String> found = new java.util.TreeSet<>();
        ConnectivityManager manager = context.getSystemService(ConnectivityManager.class);
        for (Network network : manager.getAllNetworks()) {
            NetworkCapabilities caps = manager.getNetworkCapabilities(network);
            if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
            LinkProperties properties = manager.getLinkProperties(network);
            if (properties == null) continue;
            for (LinkAddress address : properties.getLinkAddresses()) {
                InetAddress ip = address.getAddress();
                if (ip instanceof Inet4Address && (ip.isSiteLocalAddress() || ip.isLinkLocalAddress())) found.add(ip.getHostAddress());
            }
        }
        return found;
    }
    private static String hex(byte[] value) {
        StringBuilder out = new StringBuilder();
        for (byte b : value) out.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return out.toString();
    }
}

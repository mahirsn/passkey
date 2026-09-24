package sn.mahir.passkey;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Base64;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** CTAP 2.0 authenticator. Keys are generated in the Android Keystore
 *  (StrongBox when available) and never leave the device; credential metadata
 *  lives in the app's private storage. */
final class Authenticator {
    static final int OK = 0x00, ERR_INVALID_COMMAND = 0x01, ERR_INVALID_CBOR = 0x12,
            ERR_MISSING_PARAMETER = 0x14, ERR_CREDENTIAL_EXCLUDED = 0x19,
            ERR_UNSUPPORTED_ALGORITHM = 0x26, ERR_OPERATION_DENIED = 0x27,
            ERR_KEEPALIVE_CANCEL = 0x2D, ERR_NO_CREDENTIALS = 0x2E,
            ERR_USER_ACTION_TIMEOUT = 0x2F, ERR_NOT_ALLOWED = 0x30,
            ERR_PIN_NOT_SET = 0x35, ERR_OTHER = 0x7F;

    // Fixed AAGUID of this authenticator.
    static final byte[] AAGUID = hex("706173736b65792d616e64726f696431");

    /** Asks the user: fingerprint (or device PIN). Returns a CTAP status. */
    interface Ui { int confirm(String title, String detail); }

    private final SharedPreferences store;
    private final Ui ui;
    private final SecureRandom rng = new SecureRandom();
    // Credentials left for authenticatorGetNextAssertion, with the flags the
    // first assertion was really made with.
    private List<String> pending = new ArrayList<>();
    private byte[] pendingHash;
    private String pendingRp;
    private int pendingFlags;
    private Object pendingOwner;
    private long pendingUntil;

    Authenticator(Context c, Ui ui) {
        this.store = c.getSharedPreferences("creds", Context.MODE_PRIVATE);
        this.ui = ui;
    }

    /** req[0] is the command, the rest CBOR. Returns status byte + CBOR.
     *  owner: the connection asking; getNextAssertion only serves the one that
     *  made the first assertion, within 30 s. */
    synchronized byte[] handle(byte[] req, Object owner) {
        if (req.length == 0) return new byte[]{(byte) ERR_INVALID_COMMAND};
        int cmd = req[0] & 0xFF;
        if (cmd != 0x08 || owner != pendingOwner || System.currentTimeMillis() > pendingUntil)
            pending = new ArrayList<>();
        pendingOwner = owner;
        try {
            Map<Object, Object> p = req.length > 1 ? asMap(Cbor.decode(req, 1)) : new LinkedHashMap<>();
            switch (cmd) {
                case 0x04: return ok(getInfo());
                case 0x01: return makeCredential(p);
                case 0x02: return getAssertion(p);
                case 0x08: return getNextAssertion();
                default: return new byte[]{(byte) ERR_INVALID_COMMAND};
            }
        } catch (ClassCastException | IllegalArgumentException | IndexOutOfBoundsException e) {
            return new byte[]{(byte) ERR_INVALID_CBOR};
        } catch (Exception e) {
            android.util.Log.e("passkey", "ctap", e);
            return new byte[]{(byte) ERR_OTHER};
        }
    }

    private Map<Object, Object> getInfo() {
        Map<Object, Object> opts = new LinkedHashMap<>();
        opts.put("rk", true);
        opts.put("up", true);
        opts.put("uv", true);
        opts.put("plat", false);
        Map<Object, Object> m = new LinkedHashMap<>();
        List<Object> versions = new ArrayList<>();
        versions.add("FIDO_2_0");
        m.put(1, versions);
        m.put(3, AAGUID);
        m.put(4, opts);
        m.put(5, 7609);
        // No PIN (the clientPin option is never offered), but some clients only
        // use built-in UV when a protocol list is present (python-fido2).
        List<Object> pin = new ArrayList<>();
        pin.add(1);
        m.put(6, pin);
        return m;
    }

    // --- makeCredential ----------------------------------------------------------
    private byte[] makeCredential(Map<Object, Object> p) throws Exception {
        byte[] cdh = (byte[]) p.get(1L);
        Map<Object, Object> rp = asMap(p.get(2L)), user = asMap(p.get(3L));
        List<Object> algs = asList(p.get(4L));
        if (cdh == null || rp == null || user == null || algs == null) return err(ERR_MISSING_PARAMETER);
        boolean es256 = false;
        for (Object a : algs) {
            Map<Object, Object> m = asMap(a);
            if ("public-key".equals(m.get("type")) && Long.valueOf(-7).equals(m.get("alg"))) es256 = true;
        }
        if (!es256) return err(ERR_UNSUPPORTED_ALGORITHM);
        // Empty pinAuth: the client wants a touch to pick a device. There is no PIN.
        if (p.get(8L) instanceof byte[] && ((byte[]) p.get(8L)).length == 0) return err(ERR_PIN_NOT_SET);

        String rpId = (String) rp.get("id");
        Map<Object, Object> opts = asMap(p.get(7L));
        boolean rk = opts != null && Boolean.TRUE.equals(opts.get("rk"));
        String who = str(user.get("displayName"), str(user.get("name"), ""));

        List<Object> exclude = asList(p.get(5L));
        if (exclude != null) for (Object o : exclude) {
            JSONObject c = find((byte[]) asMap(o).get("id"));
            if (c != null && rpId.equals(c.getString("rp"))) {
                int s = ui.confirm("Already registered", label(rpId));
                return err(s == OK ? ERR_CREDENTIAL_EXCLUDED : s);
            }
        }
        int s = ui.confirm("Create a key", label(rpId) + (who.isEmpty() ? "" : " · " + who));
        if (s != OK) return err(s);

        // A new discoverable key replaces the old one for the same site and account.
        if (rk) {
            String uid = b64((byte[]) user.get("id"));
            for (Map.Entry<String, ?> e : store.getAll().entrySet()) {
                JSONObject o = new JSONObject((String) e.getValue());
                if (o.optBoolean("rk") && rpId.equals(o.getString("rp")) && uid.equals(o.getString("uid")))
                    delete(e.getKey());
            }
        }

        byte[] id = new byte[16];
        rng.nextBytes(id);
        KeyPair kp = newKey(alias(id));
        ECPublicKey pub = (ECPublicKey) kp.getPublic();

        JSONObject c = new JSONObject();
        c.put("rp", rpId);
        c.put("uid", b64((byte[]) user.get("id")));
        c.put("name", str(user.get("name"), ""));
        c.put("dn", str(user.get("displayName"), ""));
        c.put("rk", rk);
        c.put("n", 0);
        c.put("t", System.currentTimeMillis());
        store.edit().putString(hexs(id), c.toString()).commit();

        ByteArrayOutputStream ad = new ByteArrayOutputStream();
        ad.write(sha256(rpId));
        ad.write(0x01 | 0x04 | 0x40);              // UP | UV | AT
        ad.write(new byte[4]);                      // counter 0
        ad.write(AAGUID);
        ad.write(0); ad.write(id.length);
        ad.write(id);
        Map<Object, Object> cose = new LinkedHashMap<>();
        cose.put(1, 2);
        cose.put(3, -7);
        cose.put(-1, 1);
        cose.put(-2, u32(pub.getW().getAffineX()));
        cose.put(-3, u32(pub.getW().getAffineY()));
        ad.write(Cbor.encode(cose));

        // "packed" self attestation, signed with the credential's own key:
        // libfido2 (pamu2fcfg) refuses the "none" format.
        byte[] authData = ad.toByteArray();
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(kp.getPrivate());
        sig.update(authData);
        sig.update(cdh);
        Map<Object, Object> att = new LinkedHashMap<>();
        att.put("alg", -7);
        att.put("sig", sig.sign());

        Map<Object, Object> r = new LinkedHashMap<>();
        r.put(1, "packed");
        r.put(2, authData);
        r.put(3, att);
        return ok(r);
    }

    // --- getAssertion --------------------------------------------------------------
    private byte[] getAssertion(Map<Object, Object> p) throws Exception {
        String rpId = (String) p.get(1L);
        byte[] cdh = (byte[]) p.get(2L);
        if (rpId == null || cdh == null) return err(ERR_MISSING_PARAMETER);
        if (p.get(6L) instanceof byte[] && ((byte[]) p.get(6L)).length == 0) return err(ERR_PIN_NOT_SET);
        Map<Object, Object> opts = asMap(p.get(5L));
        boolean up = opts == null || !Boolean.FALSE.equals(opts.get("up"));
        boolean uv = opts != null && Boolean.TRUE.equals(opts.get("uv"));

        List<String> hits = new ArrayList<>();
        List<Object> allow = asList(p.get(3L));
        boolean discoverable = allow == null || allow.isEmpty();
        if (!discoverable) {
            for (Object o : allow) {
                byte[] id = (byte[]) asMap(o).get("id");
                JSONObject c = find(id);
                if (c != null && rpId.equals(c.getString("rp")) && !hits.contains(hexs(id))) hits.add(hexs(id));
            }
        } else {
            List<String[]> rks = new ArrayList<>();
            for (Map.Entry<String, ?> e : store.getAll().entrySet()) {
                JSONObject c = new JSONObject((String) e.getValue());
                // Every key can be found without an allow list, not only those
                // made with rk: sites often register with residentKey
                // "discouraged" and then offer "sign in with a passkey", which
                // asks without one. WebAuthn allows a discoverable key either way.
                if (rpId.equals(c.getString("rp")))
                    rks.add(new String[]{String.format("%020d", c.optLong("t")), e.getKey()});
            }
            rks.sort((a, b) -> b[0].compareTo(a[0]));   // newest first
            for (String[] r : rks) hits.add(r[1]);
        }
        if (hits.isEmpty()) {
            // Still ask, or a client could find out silently whether a key exists.
            // A presence-free probe (up=false) stays silent.
            if (up) ui.confirm("No key for this site", label(rpId));
            return err(ERR_NO_CREDENTIALS);
        }
        // up=false: the client only probes which credential lives here. The
        // flags stay zero, so no relying party accepts the result as a sign-in.
        if (up || uv) {
            int s = ui.confirm("Sign in", label(rpId));
            if (s != OK) return err(s);
        }
        int flags = (up ? 0x01 : 0) | (up || uv ? 0x04 : 0);
        // More accounts for one site: the rest follow via getNextAssertion,
        // made with exactly the flags this one earned.
        pending = discoverable ? new ArrayList<>(hits.subList(1, hits.size())) : new ArrayList<>();
        pendingRp = rpId;
        pendingHash = cdh;
        pendingFlags = flags;
        pendingUntil = System.currentTimeMillis() + 30_000;
        return ok(assertion(hits.get(0), rpId, cdh, flags, discoverable ? hits.size() : 0, discoverable));
    }

    private byte[] getNextAssertion() throws Exception {
        if (pending.isEmpty()) return err(ERR_NOT_ALLOWED);
        String id = pending.remove(0);
        return ok(assertion(id, pendingRp, pendingHash, pendingFlags, 0, true));
    }

    private Map<Object, Object> assertion(String idHex, String rpId, byte[] cdh, int flags,
                                          int count, boolean withUser) throws Exception {
        JSONObject c = new JSONObject(store.getString(idHex, "{}"));
        long n = c.optLong("n") + 1;
        c.put("n", n);
        store.edit().putString(idHex, c.toString()).commit();

        ByteArrayOutputStream ad = new ByteArrayOutputStream();
        ad.write(sha256(rpId));
        ad.write(flags);
        for (int s = 24; s >= 0; s -= 8) ad.write((int) (n >> s));
        byte[] authData = ad.toByteArray();

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign((PrivateKey) ks.getKey(alias(hex(idHex)), null));
        sig.update(authData);
        sig.update(cdh);

        Map<Object, Object> cred = new LinkedHashMap<>();
        cred.put("type", "public-key");
        cred.put("id", hex(idHex));
        Map<Object, Object> r = new LinkedHashMap<>();
        r.put(1, cred);
        r.put(2, authData);
        r.put(3, sig.sign());
        if (withUser) {
            Map<Object, Object> u = new LinkedHashMap<>();
            u.put("id", Base64.decode(c.getString("uid"), Base64.NO_WRAP));
            if ((flags & 0x04) != 0) {          // names only after user verification
                if (!c.optString("name").isEmpty()) u.put("name", c.getString("name"));
                if (!c.optString("dn").isEmpty()) u.put("displayName", c.getString("dn"));
            }
            r.put(4, u);
        }
        if (count > 1) r.put(5, count);
        return r;
    }

    // --- storage ------------------------------------------------------------------
    /** Not synchronized on this: handle() can wait 30 s for the user. */
    void delete(String idHex) {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            ks.deleteEntry(alias(hex(idHex)));
        } catch (Exception ignored) {}
        store.edit().remove(idHex).commit();
    }

    private JSONObject find(byte[] id) {
        if (id == null) return null;
        String s = store.getString(hexs(id), null);
        try { return s == null ? null : new JSONObject(s); } catch (Exception e) { return null; }
    }

    private static KeyPair newKey(String alias) throws Exception {
        try {
            return gen(alias, true);
        } catch (StrongBoxUnavailableException e) {
            return gen(alias, false);
        }
    }

    private static KeyPair gen(String alias, boolean strongBox) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        g.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setIsStrongBoxBacked(strongBox)
                .build());
        return g.generateKeyPair();
    }

    /** Origins like pam://myhost read as "myhost (computer sign-in)". */
    static String label(String rpId) {
        return rpId.startsWith("pam://") ? rpId.substring(6) + " (computer sign-in)" : rpId;
    }

    private static String alias(byte[] id) { return "tk_" + hexs(id); }
    private static byte[] ok(Map<Object, Object> m) {
        byte[] b = Cbor.encode(m), r = new byte[b.length + 1];
        System.arraycopy(b, 0, r, 1, b.length);
        return r;
    }
    private static byte[] err(int s) { return new byte[]{(byte) s}; }
    @SuppressWarnings("unchecked")
    private static Map<Object, Object> asMap(Object o) { return (Map<Object, Object>) o; }
    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object o) { return (List<Object>) o; }
    private static String str(Object o, String d) { return o instanceof String ? (String) o : d; }
    private static String b64(byte[] b) { return Base64.encodeToString(b == null ? new byte[0] : b, Base64.NO_WRAP); }
    static byte[] sha256(String s) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    }
    private static byte[] u32(BigInteger v) {
        byte[] b = v.toByteArray(), r = new byte[32];
        int n = Math.min(b.length, 32);
        System.arraycopy(b, b.length - n, r, 32 - n, n);
        return r;
    }
    static String hexs(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }
    static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }
}

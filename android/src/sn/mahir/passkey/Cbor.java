package sn.mahir.passkey;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** As much CBOR as CTAP2 uses: integers, byte/text strings, arrays, maps and
 *  booleans. Map keys are written in CTAP2 canonical order. */
final class Cbor {
    private Cbor() {}

    // --- encoding ------------------------------------------------------------
    static byte[] encode(Object o) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        write(out, o);
        return out.toByteArray();
    }

    private static void head(ByteArrayOutputStream out, int major, long v) {
        int m = major << 5;
        if (v < 24) out.write(m | (int) v);
        else if (v < 0x100) { out.write(m | 24); out.write((int) v); }
        else if (v < 0x10000) { out.write(m | 25); out.write((int) (v >> 8)); out.write((int) v); }
        else if (v < 0x100000000L) {
            out.write(m | 26);
            for (int s = 24; s >= 0; s -= 8) out.write((int) (v >> s));
        } else {
            out.write(m | 27);
            for (int s = 56; s >= 0; s -= 8) out.write((int) (v >> s));
        }
    }

    @SuppressWarnings("unchecked")
    private static void write(ByteArrayOutputStream out, Object o) {
        if (o instanceof Integer || o instanceof Long) {
            long v = ((Number) o).longValue();
            if (v >= 0) head(out, 0, v); else head(out, 1, -1 - v);
        } else if (o instanceof byte[]) {
            byte[] b = (byte[]) o;
            head(out, 2, b.length);
            out.write(b, 0, b.length);
        } else if (o instanceof String) {
            byte[] b = ((String) o).getBytes(StandardCharsets.UTF_8);
            head(out, 3, b.length);
            out.write(b, 0, b.length);
        } else if (o instanceof List) {
            List<Object> l = (List<Object>) o;
            head(out, 4, l.size());
            for (Object x : l) write(out, x);
        } else if (o instanceof Map) {
            Map<Object, Object> m = (Map<Object, Object>) o;
            List<byte[][]> kv = new ArrayList<>();
            for (Map.Entry<Object, Object> e : m.entrySet())
                kv.add(new byte[][]{encode(e.getKey()), encode(e.getValue())});
            // Canonical: shorter keys first, equal lengths byte by byte.
            kv.sort((a, b) -> a[0].length != b[0].length ? a[0].length - b[0].length
                    : Arrays.compareUnsigned(a[0], b[0]));
            head(out, 5, kv.size());
            for (byte[][] p : kv) { out.write(p[0], 0, p[0].length); out.write(p[1], 0, p[1].length); }
        } else if (o instanceof Boolean) {
            out.write((Boolean) o ? 0xF5 : 0xF4);
        } else {
            throw new IllegalArgumentException("cbor: " + o);
        }
    }

    // --- decoding ------------------------------------------------------------
    static Object decode(byte[] b, int off) {
        int[] pos = {off};
        return read(b, pos, 0);
    }

    private static long arg(byte[] b, int[] p, int info) {
        if (info < 24) return info;
        int n = info == 24 ? 1 : info == 25 ? 2 : info == 26 ? 4 : info == 27 ? 8 : -1;
        if (n < 0) throw new IllegalArgumentException("cbor: indefinite length");
        long v = 0;
        for (int i = 0; i < n; i++) v = (v << 8) | (b[p[0]++] & 0xFF);
        return v;
    }

    private static Object read(byte[] b, int[] p, int depth) {
        if (depth > 8) throw new IllegalArgumentException("cbor: too deep");
        int ib = b[p[0]++] & 0xFF, major = ib >> 5, info = ib & 31;
        if (major == 7) {
            if (info == 20) return Boolean.FALSE;
            if (info == 21) return Boolean.TRUE;
            if (info == 22) return null;
            throw new IllegalArgumentException("cbor: simple type " + info);
        }
        long v = arg(b, p, info);
        switch (major) {
            case 0: return v;
            case 1: return -1 - v;
            case 2: case 3: {
                if (v > b.length - p[0]) throw new IllegalArgumentException("cbor: truncated");
                byte[] s = Arrays.copyOfRange(b, p[0], p[0] + (int) v);
                p[0] += (int) v;
                return major == 2 ? s : new String(s, StandardCharsets.UTF_8);
            }
            case 4: {
                List<Object> l = new ArrayList<>();
                for (long i = 0; i < v; i++) l.add(read(b, p, depth + 1));
                return l;
            }
            case 5: {
                Map<Object, Object> m = new LinkedHashMap<>();
                for (long i = 0; i < v; i++) m.put(read(b, p, depth + 1), read(b, p, depth + 1));
                return m;
            }
            default: throw new IllegalArgumentException("cbor: tags not supported");
        }
    }
}

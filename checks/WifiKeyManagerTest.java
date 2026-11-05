package sn.mahir.passkey;

import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;

/** Run on the host JDK: exercise the engine callback path used by Android's Conscrypt sockets. */
public final class WifiKeyManagerTest {
    private static void tasks(SSLEngine engine) {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) task.run();
    }
    private static void transfer(SSLEngine engine, ByteBuffer incoming, ByteBuffer outgoing) throws Exception {
        tasks(engine);
        if (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP)
            engine.wrap(ByteBuffer.allocate(0), outgoing);
        incoming.flip();
        while (incoming.hasRemaining()) {
            SSLEngineResult result = engine.unwrap(incoming, ByteBuffer.allocate(65536));
            tasks(engine);
            if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW
                    || result.bytesConsumed() == 0 && result.bytesProduced() == 0) break;
        }
        incoming.compact();
    }
    public static void main(String[] args) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (FileInputStream input = new FileInputStream(args[0])) { store.load(input, "test-only".toCharArray()); }
        PrivateKey key = (PrivateKey) store.getKey("wifi", "test-only".toCharArray());
        X509Certificate cert = (X509Certificate) store.getCertificate("wifi");
        WifiKeyManager manager = new WifiKeyManager("wifi", key, cert);
        if (manager.chooseServerAlias("RSA", null, null) != null) throw new AssertionError("Wrong key type selected");
        if (!"wifi".equals(manager.chooseServerAlias("EC_EC", null, null))) throw new AssertionError("EC key not selected");
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(store);
        for (String protocol : new String[]{"TLSv1.3", "TLSv1.2"}) {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(new KeyManager[]{manager}, trust.getTrustManagers(), null);
            SSLEngine server = context.createSSLEngine(), client = context.createSSLEngine("passkey.wifi", 40719);
            server.setUseClientMode(false); client.setUseClientMode(true);
            server.setEnabledProtocols(new String[]{protocol}); client.setEnabledProtocols(new String[]{protocol});
            server.beginHandshake(); client.beginHandshake();
            ByteBuffer toServer = ByteBuffer.allocate(65536), toClient = ByteBuffer.allocate(65536);
            for (int i = 0; i < 100; i++) {
                transfer(client, toClient, toServer);
                transfer(server, toServer, toClient);
                if (client.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
                        && server.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) break;
                if (i == 99) throw new AssertionError("Handshake stalled");
            }
            if (!protocol.equals(client.getSession().getProtocol())) throw new AssertionError("Wrong negotiated protocol");
            System.out.println(protocol + " engine handshake passed");
        }
    }
}

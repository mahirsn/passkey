package sn.mahir.passkey;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.SSLEngine;

/** Conscrypt server sockets use the engine callback; both paths must select the same key. */
final class WifiKeyManager extends X509ExtendedKeyManager {
    private final String alias;
    private final PrivateKey key;
    private final X509Certificate certificate;
    WifiKeyManager(String alias, PrivateKey key, X509Certificate certificate) {
        this.alias = alias; this.key = key; this.certificate = certificate;
    }
    public String[] getClientAliases(String type, Principal[] issuers) { return null; }
    public String chooseClientAlias(String[] types, Principal[] issuers, Socket socket) { return null; }
    public String[] getServerAliases(String type, Principal[] issuers) {
        return "EC".equals(type) || (type != null && type.startsWith("EC_")) ? new String[]{alias} : null;
    }
    public String chooseServerAlias(String type, Principal[] issuers, Socket socket) {
        return getServerAliases(type, issuers) == null ? null : alias;
    }
    @Override public String chooseEngineServerAlias(String type, Principal[] issuers, SSLEngine engine) {
        return chooseServerAlias(type, issuers, null);
    }
    @Override public String chooseEngineClientAlias(String[] types, Principal[] issuers, SSLEngine engine) { return null; }
    public X509Certificate[] getCertificateChain(String name) { return alias.equals(name) ? new X509Certificate[]{certificate} : null; }
    public PrivateKey getPrivateKey(String name) { return alias.equals(name) ? key : null; }
}

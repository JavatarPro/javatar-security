package pro.javatar.security.jwt.utils;


import pro.javatar.security.jwt.exception.PemException;

import org.bouncycastle.openssl.PEMWriter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Utility classes to extract PublicKey, PrivateKey, and X509Certificate from openssl generated PEM files
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public final class PemUtils {

    static {
        BouncyIntegration.init();
    }

    private PemUtils() {
    }

    /*
     * Decode a X509 Certificate from a PEM string
     */
    public static X509Certificate decodeCertificate(String cert) {
        if (cert == null) {
            return null;
        }

        try {
            byte[] der = pemToDer(cert);
            ByteArrayInputStream bis = new ByteArrayInputStream(der);
            return DerUtils.decodeCertificate(bis);
        } catch (Exception e) {
            throw new PemException(e);
        }
    }

    /*
     * Decode a Public Key from a PEM string
     */
    public static PublicKey decodePublicKey(String pem) {
        if (pem == null) {
            return null;
        }

        try {
            byte[] der = pemToDer(pem);
            return DerUtils.decodePublicKey(der);
        } catch (Exception e) {
            throw new PemException(e);
        }
    }

    /*
     * Encode a Key to a PEM string
     */
    public static String encodeKey(Key key) {
        return encode(key);
    }

    /*
     * Encode a X509 Certificate to a PEM string
     */
    public static String encodeCertificate(Certificate certificate) {
        return encode(certificate);
    }

    private static String encode(Object obj) {
        if (obj == null) {
            return null;
        }

        try {
            StringWriter writer = new StringWriter();
            PEMWriter pemWriter = new PEMWriter(writer);
            pemWriter.writeObject(obj);
            pemWriter.flush();
            pemWriter.close();
            String s = writer.toString();
            return PemUtils.removeKeyBeginEnd(s);
        } catch (Exception e) {
            throw new PemException(e);
        }
    }

    private static byte[] pemToDer(String pem) throws IOException {
        String result = removeKeyBeginEnd(pem);
        return Base64.decode(result);
    }

    public static String removeKeyBeginEnd(String pem) {
        String result = pem.replaceAll("-----BEGIN (.*)-----", "")
                .replaceAll("-----END (.*)----", "")
                .replaceAll("\r\n", "")
                .replaceAll("\n", "");
        return result.trim();
    }

}

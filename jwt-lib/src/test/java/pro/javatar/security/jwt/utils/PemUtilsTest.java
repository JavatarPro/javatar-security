package pro.javatar.security.jwt.utils;

import org.junit.jupiter.api.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.security.PublicKey;

public class PemUtilsTest {

    @Test
    void decodePublicKey() {
        String pem =
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmt08Q3U/oE45mAgioJlM/KK5aUPXOlbq+2o31U4cDPhU/ps0/a9B2k+VyjpUwG5fBZcuyudbAtppSabrfsQ2BRQM9C/n6KQ2PGVynIVgXFWynjfmNXDeomdyxRhn8jenioVvJjk1S5NeTgcrxBaia1R85CL3x0YY5xER2KzRdfAXQCwWC40EEtv4MzTeLkKdB7J/sLf+sV9+HX/YUfU3Jk2X+rWU7C9aSrtNRdaUbY+dGsPACFdw0gNIBaN5vxNKSkx3V1iqLa/7hRXzjx2cFgBJDKO/Io9sLkyhOrxX6mu5QpR1w228eDH4s1zShg0QHDOY/Tmkox9URsFcYZ+DSwIDAQAB";
        PublicKey publicKey = PemUtils.decodePublicKey(pem);
        assertThat(publicKey.getAlgorithm(), is("RSA"));
        assertThat(publicKey.getFormat(), is("X.509"));
    }
}
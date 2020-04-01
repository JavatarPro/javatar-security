package pro.javatar.security.oidc.utils;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class TestHelper {

    public static String getStub(String classpathFile) throws Exception {
        return new String(Files.readAllBytes(
                Paths.get(StringUtilsTest.class.getClassLoader().getResource(classpathFile).toURI())));
    }

    public static InputStream getStubAsInputStream(String classpathFile) {
        return StringUtilsTest.class.getClassLoader().getResourceAsStream(classpathFile);
    }

}

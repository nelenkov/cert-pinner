package org.nick.certpinner;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.provider.Settings;
import android.util.Base64;
import android.util.Log;

public class CertPinner {

    private static final String TAG = CertPinner.class.getSimpleName();

    private static final char[] DIGITS = { '0', '1', '2', '3', '4', '5', '6',
            '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
            'x', 'y', 'z' };

    private static final char[] UPPER_CASE_DIGITS = { '0', '1', '2', '3', '4',
            '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
            'V', 'W', 'X', 'Y', 'Z' };

    private static final String PINLIST_CERTIFICATE_KEY = "config_update_certificate";

    private static final String EXTRA_CONTENT_PATH = "CONTENT_PATH";
    private static final String EXTRA_REQUIRED_HASH = "REQUIRED_HASH";
    private static final String EXTRA_SIGNATURE = "SIGNATURE";
    private static final String EXTRA_VERSION_NUMBER = "VERSION";

    public static final String PIN_LIST_SIGNING_CERT = ""
            + "MIICqDCCAZACCQDM8+2I0Zho4zANBgkqhkiG9w0BAQUFADAWMRQwEgYDVQQDDAtj"
            + "ZXJ0LXBpbm5lcjAeFw0xMjEyMDUwNzQ3MjhaFw0xMzEyMDUwNzQ3MjhaMBYxFDAS"
            + "BgNVBAMMC2NlcnQtcGlubmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC"
            + "AQEAvLQnLWQxBmguxvmJYASTCZjeSX107T/HKSA4memibzJBlDUKhC4Mak560eT8"
            + "XA6bfF2ituTddddzHsndzlKWOLq1qUpcuQS1kYJqJpIPx3j9x2lAITH06I0KspAL"
            + "EgrqUCLmTuI3irCGxm8SlNILmbI0ZX0U0kG13T75L6dKpF+t/af4xwHTvnp++6R1"
            + "DIo7AVd4waMYmX7DgC2NXHJSfow7ovpzbHPHQ8SJb14JTiowHS98VLcFbpW1UQLp"
            + "hiDI4wQy/V9NaHmXGtl2gdK8pACAvaym5SQZG9ETYS+joMWaGFdd29hIZEIarM7b"
            + "rVawQYYGzOJqUgLnG0kOIWO0swIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBG299R"
            + "FuwjLkZ21MYydPDUnyUkWSTT+JmAROkjs/y3KgnKaOXD2uGd98HovXRtMtkplNNw"
            + "84j6eD4u4TeUxlmLzBQ6BtUGPIj8j2NLVyTTugJaUfJRcZVZRkWyIX9euJg9AqwG"
            + "pWPsAmGVOhxY/j3wfyQ3upCKJh/kkc4UkIY7WJunJYC1PPBjDNWUBF306buUMT9T"
            + "n2pOFCJpLdHmSRpKJKp7vidAH6JjHTbbapqCc5enmrBTnG9OziFhWoTmc4gw0/r9"
            + "bP7uvPGbwkn0cbpIncQvzG9Gf0w2Qxgbcr/djnD3XmiPCkZeFGKqRINt+rT+XCgO"
            + "e5++IXfVqRSDSmsH";

    private static final String PIN_LIST_SIGNING_KEY = ""
            + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8tCctZDEGaC7G"
            + "+YlgBJMJmN5JfXTtP8cpIDiZ6aJvMkGUNQqELgxqTnrR5PxcDpt8XaK25N1113Me"
            + "yd3OUpY4urWpSly5BLWRgmomkg/HeP3HaUAhMfTojQqykAsSCupQIuZO4jeKsIbG"
            + "bxKU0guZsjRlfRTSQbXdPvkvp0qkX639p/jHAdO+en77pHUMijsBV3jBoxiZfsOA"
            + "LY1cclJ+jDui+nNsc8dDxIlvXglOKjAdL3xUtwVulbVRAumGIMjjBDL9X01oeZca"
            + "2XaB0rykAIC9rKblJBkb0RNhL6OgxZoYV13b2EhkQhqsztutVrBBhgbM4mpSAucb"
            + "SQ4hY7SzAgMBAAECggEAMgdVJ6ybbsZqOGhp6mHsFaxIqpUvTcMN6zJWrz+IyBA7"
            + "4K4bRqXqtrhtyX37BfD9egBdJj4RFK/1HmGIg63Tk+C0TtifMpI0DQrVV7p7onfK"
            + "WHboAKT8+DaEcojL1pG8Q1itVJaXARcB9FP4SipR1wKu74U04vV24NxUNjUVDfS2"
            + "Yy7ekb8DXWvEI9ZgfHNAwQBZZ2rrKpX/8zrwCH9iKoAKfq0fmaoqezUcFI0b//1w"
            + "CY0BLqX7tksf6nFTBvR1fnIktKmzrfi70DwiBzVk5GWa85BimZXyB55m2eQ8SE+e"
            + "sM/UixqiQLjVa4L16AG2ggBhuujkDJGw4Nl2NWwPKQKBgQD6eahLnlQaWUlsHXs4"
            + "I7CxT5pu1qJE/Ii1Ih9iiyK6dF/0Co84O7TuIyNFeiOqShfVAAxydxQWAEq9ZXuK"
            + "8Vomdv61StHRE2MwxydAigyVSzt032Xct2X2HQCiDQ0wz1lwpm0+WPeiPMYRA2It"
            + "e4w7VEtQuC7DBWcJxXUSFwPDRQKBgQDA3bHEhIVHOzaPp4F5VeJB3PsMIakyLpo6"
            + "I19Jqe+fcBVtdyfR59xbmsd+1tgWqByNIqHIYQt+7yCxrPNkDtpmj1Q57L7Hq9HC"
            + "D2QWmDRNXPJgjkRXbqMbFviouTUOBBfxglIBh2Xwyl2UsyDl9mPE67agZzO0p/KU"
            + "yvEvo9pblwKBgFxLeeUrWUhAQFrTXjUoiZI8h+Zxtmd/OoysHy57oHdeLIFLZszM"
            + "y3W4guW2BPBZzwBQvUVsdX1J7EBv5Z8kIhjsXhzFjhzhbPprWB5jABH/H9CIBQvY"
            + "lHyk4TfVYVfr/8QPv09rDwy8IivguEuUK+8st3ft9mUsV3R1Sxc4Xc2VAoGAFVRv"
            + "ZJyDYO1bi2erGhA1hbM60IyoebRNukBPOYZhyfBLbl/PN5e89ySXC6AXJepRvgom"
            + "elLBQriPlRbblCVQYidX2VAliU+nUx8Aor8SibvN0n/pbwH9Z/GSbpaNF4+8Vilj"
            + "iGfBDnBTCS8GZGhrgEvRVswTG9e3LF2Fbw9gBuECgYEA8Iwjm4Ij58FMkRTv++0V"
            + "XT3NJEcmIvLgZDyedQ4eeFeg/pHPbowJzBAurx4xjcHFa90P8FXTNymIfITuzJXb"
            + "P44yGhcyRIvVo0FLehx8Fp9JhGgY7ZJzcR3VzsudIGeBZSax7K96DYAwjir4B/a3"
            + "tUxiEotCBVJAaEOH7vJ9SV4=";

    private Context ctx;

    private Signature signer;

    private KeyStore systemTrustStore;
    private PKIXParameters pkixParams;
    private CertPathValidator certPathValidator;
    private CertificateFactory certificateFactory;

    public CertPinner(Context ctx) {
        this.ctx = ctx;
        try {
            signer = Signature.getInstance("SHA512withRSA");

            systemTrustStore = loadSystemTrustStre();
            pkixParams = createPkixParams(systemTrustStore);
            certificateFactory = CertificateFactory.getInstance("X509");
            certPathValidator = CertPathValidator.getInstance("PKIX");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public void setPinListSigningCertificate(boolean overwrite)
            throws Exception {
        String cert = Settings.Secure.getString(ctx.getContentResolver(),
                PINLIST_CERTIFICATE_KEY);
        if (cert == null || overwrite) {
            X509Certificate c = createCertificate();
            Log.d(TAG, "Trying to put pin list signing certificate in "
                    + PINLIST_CERTIFICATE_KEY + ": "
                    + c.getSubjectDN().getName());
            putCertificate();
        }
        Log.d(TAG, PINLIST_CERTIFICATE_KEY + "= " + cert);
    }

    public String getNextVersion() throws Exception {
        int currentVersion = Integer.parseInt(readCurrentVersion());
        return Integer.toString(currentVersion + 1);
    }

    // cannot read w/ default perms. Use su
    private String readCurrentVersion() throws Exception {
        String metadataFilename = "/data/misc/keychain/metadata/version";
        if (SuShell.canGainSu(ctx)) {
            List<String> result = SuShell.runWithSu("ls " + metadataFilename);
            if (result.isEmpty()) {
                return "0";
            }

            if (result.get(0).contains("No such file")) {
                return "0";
            }

            result = SuShell.runWithSu("cat " + metadataFilename);
            // shouldn't really happen...
            if (result.isEmpty()) {
                return "0";
            }

            return result.get(0).trim();
        }
        // this will most probably fail, but try anyway
        else {
            File f = new File(metadataFilename);
            if (!f.exists()) {
                return "0";
            }

            return readFileAsString(f.getAbsolutePath());
        }
    }

    private void putCertificate() {
        Settings.Secure.putString(ctx.getContentResolver(),
                PINLIST_CERTIFICATE_KEY, PIN_LIST_SIGNING_CERT);
    }

    private static String getCurrentHash(String content) throws Exception {
        if (content == null) {
            return "0";
        }
        MessageDigest dgst = MessageDigest.getInstance("SHA512");
        byte[] encoded = content.getBytes();
        byte[] fingerprint = dgst.digest(encoded);
        return bytesToHexString(fingerprint, false);
    }

    public static String bytesToHexString(byte[] bytes, boolean upperCase) {
        char[] digits = upperCase ? UPPER_CASE_DIGITS : DIGITS;
        char[] buf = new char[bytes.length * 2];
        int c = 0;
        for (byte b : bytes) {
            buf[c++] = digits[(b >> 4) & 0xf];
            buf[c++] = digits[b & 0xf];
        }
        return new String(buf);
    }

    public static String getHashOfCurrentContent() throws Exception {
        String content = readFileAsString("/data/misc/keychain/pins");
        return getCurrentHash(content);
    }

    public static String readFileAsString(String path) throws IOException {
        File f = new File(path);
        if (!f.exists()) {
            return null;
        }

        FileInputStream fis = new FileInputStream(path);
        byte[] data = new byte[fis.available()];
        fis.read(data);
        fis.close();

        return new String(data, "ASCII");
    }

    private static PrivateKey createKey() throws Exception {
        byte[] derKey = Base64.decode(PIN_LIST_SIGNING_KEY.getBytes(),
                Base64.DEFAULT);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(derKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(keySpec);
    }

    private X509Certificate createCertificate() throws Exception {
        return createCertificate(PIN_LIST_SIGNING_CERT);
    }

    private static X509Certificate createCertificate(String certStr)
            throws Exception {
        byte[] derCert = Base64.decode(certStr.getBytes(), Base64.DEFAULT);
        InputStream istream = new ByteArrayInputStream(derCert);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(istream);
    }

    @SuppressWarnings("deprecation")
    @SuppressLint("WorldReadableFiles")
    public String makeTemporaryContentFile(String content) throws Exception {
        FileOutputStream fw = ctx.openFileOutput("content.txt",
                Context.MODE_WORLD_READABLE);
        fw.write(content.getBytes(), 0, content.length());
        fw.close();

        return ctx.getFilesDir() + "/content.txt";
    }

    public String createSignature(String content, String version,
            String requiredHash) throws Exception {
        signer.initSign(createKey());
        signer.update(content.trim().getBytes());
        signer.update(version.trim().getBytes());
        signer.update(requiredHash.getBytes());
        String sig = new String(Base64.encode(signer.sign(), Base64.DEFAULT));

        return sig;
    }

    public boolean verifySignature(String content, String version,
            String requiredPrevious, String signature, X509Certificate cert)
            throws Exception {
        signer.initVerify(cert);
        signer.update(content.trim().getBytes());
        signer.update(version.trim().getBytes());
        signer.update(requiredPrevious.trim().getBytes());

        return signer
                .verify(Base64.decode(signature.getBytes(), Base64.DEFAULT));
    }

    public void sendIntent(String contentPath, String version, String required,
            String sig) {
        Intent i = new Intent();
        i.setAction("android.intent.action.UPDATE_PINS");
        i.putExtra(EXTRA_CONTENT_PATH, contentPath);
        i.putExtra(EXTRA_VERSION_NUMBER, version);
        i.putExtra(EXTRA_REQUIRED_HASH, required);
        i.putExtra(EXTRA_SIGNATURE, sig);
        ctx.sendBroadcast(i);
    }

    public static String getFingerprint(X509Certificate cert)
            throws NoSuchAlgorithmException {
        MessageDigest dgst = MessageDigest.getInstance("SHA512");
        byte[] encoded = cert.getPublicKey().getEncoded();
        byte[] fingerprint = dgst.digest(encoded);

        return bytesToHexString(fingerprint, false);
    }

    public static String getChromeFingerprint(X509Certificate cert)
            throws NoSuchAlgorithmException {
        MessageDigest dgst = MessageDigest.getInstance("SHA1");
        byte[] encoded = cert.getPublicKey().getEncoded();
        byte[] fingerprint = dgst.digest(encoded);

        return "sha1/" + Base64.encodeToString(fingerprint, Base64.DEFAULT);
    }

    public X509Certificate getTrustAnchor(X509Certificate[] chain)
            throws CertificateException {
        try {
            CertPath certPath = certificateFactory.generateCertPath(Arrays
                    .asList(chain));
            PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) certPathValidator
                    .validate(certPath, pkixParams);

            if (result == null) {
                return null;
            }

            return result.getTrustAnchor().getTrustedCert();
        } catch (CertPathValidatorException e) {
            return null;
        } catch (InvalidAlgorithmParameterException e) {
            throw new CertificateException(e);
        }
    }

    private static KeyStore loadSystemTrustStre() {
        try {
            KeyStore result = KeyStore.getInstance("AndroidCAStore");
            result.load(null, null);

            return result;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static PKIXParameters createPkixParams(KeyStore trustStore) {
        try {
            HashSet<TrustAnchor> trusted = new HashSet<TrustAnchor>();
            for (Enumeration<String> aliases = trustStore.aliases(); aliases
                    .hasMoreElements();) {
                String alias = aliases.nextElement();
                X509Certificate cert = (X509Certificate) trustStore
                        .getCertificate(alias);

                if (cert != null) {
                    trusted.add(new TrustAnchor(cert, null));
                }
            }

            PKIXParameters result = new PKIXParameters(trusted);
            result.setRevocationEnabled(false);

            return result;
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

}

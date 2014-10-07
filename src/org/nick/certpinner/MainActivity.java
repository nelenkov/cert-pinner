package org.nick.certpinner;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.params.HttpClientParams;
import org.apache.http.conn.ManagedClientConnection;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;

import android.app.Activity;
import android.net.http.X509TrustManagerExtensions;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.StrictMode;
import android.os.StrictMode.ThreadPolicy;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity implements OnClickListener {

    private static final String TAG = MainActivity.class.getSimpleName();

    private TextView messageText;
    private EditText urlText;
    private Button pinButton;
    private Button checkButton;
    private Button checkHcButton;

    private CertPinner pinner;
    private TrustManagerFactory tmf;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        StrictMode.setThreadPolicy(ThreadPolicy.LAX);
        requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        messageText = (TextView) findViewById(R.id.message);
        urlText = (EditText) findViewById(R.id.url_text);
        pinButton = (Button) findViewById(R.id.pin_button);
        pinButton.setOnClickListener(this);
        checkButton = (Button) findViewById(R.id.check_button);
        checkButton.setOnClickListener(this);
        checkHcButton = (Button) findViewById(R.id.check_hc_button);
        checkHcButton.setOnClickListener(this);

        // HttpURLConnection settings
        // disable response caching
        android.net.http.HttpResponseCache.setDefault(null);
        // disable keepAlive
        System.setProperty("http.keepAlive", "false");
        // don't follow redirects
        HttpsURLConnection.setFollowRedirects(false);

        pinner = new CertPinner(this);

        try {
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory
                    .getDefaultAlgorithm());
            tmf.init((KeyStore) null);

            // do not overwrite
            pinner.setPinListSigningCertificate(false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    public void onClick(View v) {
        final String urlStr = urlText.getText().toString();

        try {
            if (v.getId() == R.id.pin_button) {
                final URL url = new URL(urlStr);

                new AsyncTask<Void, String, String>() {

                    @Override
                    protected void onPreExecute() {
                        messageText.setText("Connecting to " + url.toString()
                                + "\n");
                        setProgressBarIndeterminateVisibility(true);
                        toggleUiState(false);
                    }

                    @Override
                    protected String doInBackground(Void... params) {
                        StringBuilder message = new StringBuilder();
                        try {
                            HttpsURLConnection conn = (HttpsURLConnection) url
                                    .openConnection();
                            conn.setRequestMethod("GET");

                            try {
                                conn.connect();
                            } catch (Exception e) {
                                Log.e(TAG,
                                        "Error connecting w/ HttpsURLConnection: "
                                                + e.getMessage(), e);
                                message.append("Error w/ HttpsURLConnection: "
                                        + e.getMessage());

                                return message.toString();
                            }
                            publishProgress(String.format(
                                    "Connected using %s\n",
                                    conn.getCipherSuite()));


                            Certificate[] certs =
                                    conn.getServerCertificates();

                            X509Certificate[] urlChain = new X509Certificate[certs.length];
                            for (int i = 0; i<certs.length;i++){
                                urlChain[i] = (X509Certificate)certs[i];
                            }

                            publishProgress("Got server certificates: "
                                    + urlChain.length + "\n\n");

                            StringBuilder pinEntryBuff = new StringBuilder();
                            // enforcing
                            pinEntryBuff.append(String.format("%s=true|",
                                    url.getHost()));

                            int certNum = 1;
                            for (int i = 0; i < urlChain.length; i++) {
                                X509Certificate cert = urlChain[i];
                                // XXX far from ideal, but good enough for quick
                                // testing
                                // and we don't want to depend on BC
                                String dn = cert.getSubjectX500Principal()
                                        .getName();
                                publishProgress(String.format(
                                        "Cert %d: Subject DN = %s\n", certNum,
                                        dn));
                                if (dn.contains(url.getHost())
                                        || dn.contains("*")) {
                                    // skip host cert
                                    publishProgress("Skipping host certificate \n\n");
                                    continue;
                                }

                                publishProgress(String
                                        .format("Adding cert %d to pin entry for '%s'\n\n",
                                                certNum, url.getHost()));
                                Log.d(TAG,
                                        "Chrome fingerprint: "
                                                + CertPinner
                                                        .getChromeFingerprint(cert));
                                pinEntryBuff.append(CertPinner
                                        .getFingerprint(cert));
                                if (i != urlChain.length - 1) {
                                    pinEntryBuff.append(",");
                                }
                                certNum++;
                            }

                            X509Certificate trustAnchor = pinner
                                    .getTrustAnchor(urlChain);
                            if (trustAnchor != null) {
                                publishProgress(String
                                        .format("Adding cert (trust anchor) S=%s to pin entry for '%s'\n\n",
                                                trustAnchor
                                                        .getSubjectX500Principal()
                                                        .getName(), url
                                                        .getHost()));
                                Log.d(TAG,
                                        "Chrome fingerprint: "
                                                + CertPinner
                                                        .getChromeFingerprint(trustAnchor));
                                if (pinEntryBuff
                                        .charAt(pinEntryBuff.length() - 1) != '|') {
                                    pinEntryBuff.append(",");
                                }
                                pinEntryBuff.append(CertPinner
                                        .getFingerprint(trustAnchor));
                            }

                            conn.disconnect();

                            String pinEntry = pinEntryBuff.toString();
                            Log.d(TAG, String.format("Pin entry for %s = '%s'",
                                    url.getHost(), pinEntry));

                            String content = CertPinner
                                    .readFileAsString("/data/misc/keychain/pins");
                            if (content == null) {
                                content = pinEntry;
                            } else {
                                content = content += "\n";
                                content = content += pinEntry;
                            }
                            Log.d(TAG, "Pin list content: " + content);
                            String contentPath = pinner
                                    .makeTemporaryContentFile(content);
                            publishProgress("Pin list contentPath: "
                                    + contentPath + "\n");
                            String version = pinner.getNextVersion();
                            publishProgress("Pin list next version: " + version
                                    + "\n");
                            String currentHash = CertPinner
                                    .getHashOfCurrentContent();
                            publishProgress("Pin list current hash: "
                                    + currentHash + "\n");
                            String sig = pinner.createSignature(content,
                                    version, currentHash);
                            publishProgress("Pin list signature : " + sig
                                    + "\n\n");

                            publishProgress("Sending 'android.intent.action.UPDATE_PINS' intent");
                            pinner.sendIntent(contentPath, version,
                                    currentHash, sig);

                            return message.toString();
                        } catch (Exception e) {
                            Log.e(TAG,
                                    "Error pinning certificates: "
                                            + e.getMessage(), e);
                            message.append("Error pinning certificates from "
                                    + url.toString() + ": " + e.getMessage());

                            return message.toString();
                        }
                    }

                    @Override
                    protected void onProgressUpdate(String... progress) {
                        messageText.append(progress[0]);
                    }

                    @Override
                    protected void onPostExecute(String result) {
                        setProgressBarIndeterminateVisibility(false);
                        toggleUiState(true);

                        messageText.append(result);
                    }

                }.execute();
            } else if (v.getId() == R.id.check_button) {
                final URL url = new URL(urlStr);
                new AsyncTask<Void, Void, String>() {

                    @Override
                    protected void onPreExecute() {
                        messageText.setText("Connecting to " + url.toString()
                                + "\n");
                        setProgressBarIndeterminateVisibility(true);
                        toggleUiState(false);
                    }

                    @Override
                    protected String doInBackground(Void... params) {
                        StringBuilder message = new StringBuilder();
                        try {
                            HttpsURLConnection conn = (HttpsURLConnection) url
                                    .openConnection();
                            conn.setRequestMethod("GET");
                            Log.d(TAG, "Opening connection to " + url);
                            try {
                                conn.connect();
                            } catch (Exception e) {
                                Log.e(TAG,
                                        "Error connecting w/ HttpsURLConnection: "
                                                + e.getMessage(), e);
                                message.append("Error connecting w/ HttpsURLConnection: "
                                        + e.getMessage());

                                return message.toString();
                            }

                            message.append("Connected using: "
                                    + conn.getCipherSuite() + "\n");
                            message.append(String.format("Response: %d %s\n\n",
                                    conn.getResponseCode(),
                                    conn.getResponseMessage()));

                            Log.d(TAG, "Got server certificates: ");
                            X509Certificate[] chain = (X509Certificate[]) conn
                                    .getServerCertificates();
                            try {
                                message.append(extendedVerify(url, chain));
                            } catch (CertificateException e) {
                                Log.e(TAG,
                                        "Error verifying chain w/ X509TrustManagerExtensions: "
                                                + e.getMessage(), e);
                                message.append("Error verifying chain w/ X509TrustManagerExtensions: "
                                        + e.getMessage());
                            }

                            readToEnd(conn);

                            return message.toString();
                        } catch (Exception e) {
                            Log.e(TAG,
                                    "Error connecting w/ HttpsURLConnection: "
                                            + e.getMessage(), e);
                            message.append("Error connecting: "
                                    + e.getMessage());

                            return message.toString();
                        }
                    }

                    protected void onPostExecute(String result) {
                        setProgressBarIndeterminateVisibility(false);
                        toggleUiState(true);

                        messageText.append(result);
                    }
                }.execute();
            } else if (v.getId() == R.id.check_hc_button) {
                final URL url = new URL(urlStr);
                new AsyncTask<Void, Void, String>() {

                    @Override
                    protected void onPreExecute() {
                        messageText.setText("Connecting to " + url.toString()
                                + "\n");
                        setProgressBarIndeterminateVisibility(true);
                        toggleUiState(false);
                    }

                    @Override
                    protected String doInBackground(Void... params) {
                        StringBuilder message = new StringBuilder();
                        try {
                            DefaultHttpClient hc = createHttpClient();

                            HttpContext context = new BasicHttpContext();
                            HttpGet get = new HttpGet(urlStr);

                            HttpResponse response = null;
                            try {
                                response = hc.execute(get, context);
                            } catch (Exception e) {
                                Log.e(TAG, "Error connecting w/ HttpClient: "
                                        + e.getMessage(), e);
                                message.append("Error connecting w/ HttpClient: "
                                        + e.getMessage());

                                return message.toString();
                            }

                            message.append("Connected using: "
                                    + (String) context
                                            .getAttribute("cipher_suite")
                                    + "\n");
                            message.append("Response: "
                                    + response.getStatusLine() + "\n\n");

                            String html = EntityUtils.toString(response
                                    .getEntity());

                            X509Certificate[] peerCertificates = (X509Certificate[]) context
                                    .getAttribute("peer_certificates");
                            try {
                                message.append(extendedVerify(new URL(get
                                        .getURI().toString()), peerCertificates));
                            } catch (CertificateException e) {
                                Log.e(TAG,
                                        "Error verifying chain w/ X509TrustManagerExtensions: "
                                                + e.getMessage(), e);
                                message.append("Error verifying chain w/ X509TrustManagerExtensions: "
                                        + e.getMessage());
                            }

                            return message.toString();
                        } catch (Exception e) {
                            Log.e(TAG,
                                    "Error connecting w/ HttpClient: "
                                            + e.getMessage(), e);
                            message.append("Error connecting w/ HttpClient:: "
                                    + e.getMessage());

                            return message.toString();
                        }
                    }

                    @Override
                    protected void onPostExecute(String result) {
                        setProgressBarIndeterminateVisibility(false);
                        toggleUiState(true);

                        messageText.append(result);
                    }
                }.execute();
            }

        } catch (Exception e) {
            Log.e(TAG, "Error: " + e.getMessage(), e);
            Toast.makeText(this, "Error: " + e.getMessage(), Toast.LENGTH_LONG)
                    .show();
        }
    }

    private void toggleUiState(boolean enable) {
        urlText.setEnabled(enable);
        pinButton.setEnabled(enable);
        checkButton.setEnabled(enable);
        checkHcButton.setEnabled(enable);
    }

    private DefaultHttpClient createHttpClient() {
        DefaultHttpClient hc = new DefaultHttpClient();
        // don't follow redirects
        HttpParams params = hc.getParams();
        HttpClientParams.setRedirecting(params, false);
        // save peer certificates and cipher suite
        hc.addResponseInterceptor(new HttpResponseInterceptor() {
            @Override
            public void process(HttpResponse response, HttpContext context)
                    throws HttpException, IOException {
                ManagedClientConnection routedConnection = (ManagedClientConnection) context
                        .getAttribute(ExecutionContext.HTTP_CONNECTION);
                if (routedConnection.isSecure()) {
                    Certificate[] certificates = routedConnection
                            .getSSLSession().getPeerCertificates();
                    context.setAttribute("peer_certificates", certificates);
                    context.setAttribute("cipher_suite", routedConnection
                            .getSSLSession().getCipherSuite());
                }
            }
        });
        return hc;
    }

    private void readToEnd(HttpsURLConnection conn) throws IOException {
        InputStream is = conn.getInputStream();

        byte[] buffer = new byte[1024];
        int read = 0;
        while ((read = is.read(buffer)) != -1) {
            // fos.write(buffer, 0, read);
        }
        is.close();
    }

    private String extendedVerify(URL url, X509Certificate[] chain)
            throws CertificateException {
        logChain(chain);

        StringBuilder message = new StringBuilder();

        // recreate each time to pick up pin list changes
        X509TrustManagerExtensions tmx = createTmExtensions();
        Log.d(TAG, "Trying to verify server chain with "
                + tmx.getClass().getSimpleName());
        message.append("X509TrustManagerExtensions verify result: \n");
        List<X509Certificate> verifiedChain = tmx.checkServerTrusted(chain,
                "RSA", url.getHost());
        message.append(String.format(
                "\nChain for '%s' verifies. Num certs: %d\n", url.toString(),
                verifiedChain.size()));
        message.append("\n");
        printChain(verifiedChain, message);

        return message.toString();
    }

    private void logChain(X509Certificate[] chain) {
        for (X509Certificate c : chain) {
            Log.d(TAG, String.format("S:%s\nI:%s", c.getSubjectX500Principal()
                    .getName(), c.getIssuerX500Principal().getName()));
        }
    }

    private void printChain(List<X509Certificate> verifiedChain,
            StringBuilder message) {
        for (X509Certificate c : verifiedChain) {
            Log.d(TAG, "cert=" + c.toString());
            Log.d(TAG, "*******************************************");
            message.append(String.format("S:%s\nI:%s\n\n", c
                    .getSubjectX500Principal().getName(), c
                    .getIssuerX500Principal().getName()));
        }
    }

    private X509TrustManagerExtensions createTmExtensions() {
        X509TrustManagerExtensions tmx = new X509TrustManagerExtensions(
                (X509TrustManager) (tmf.getTrustManagers()[0]));
        return tmx;
    }

}

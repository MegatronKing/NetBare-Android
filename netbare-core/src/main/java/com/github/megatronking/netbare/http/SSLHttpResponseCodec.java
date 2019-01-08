/*  NetBare - An android network capture and injection library.
 *  Copyright (C) 2018-2019 Megatron King
 *  Copyright (C) 2018-2019 GuoShi
 *
 *  NetBare is free software: you can redistribute it and/or modify it under the terms
 *  of the GNU General Public License as published by the Free Software Found-
 *  ation, either version 3 of the License, or (at your option) any later version.
 *
 *  NetBare is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 *  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 *  PURPOSE. See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along with NetBare.
 *  If not, see <http://www.gnu.org/licenses/>.
 */
package com.github.megatronking.netbare.http;

import android.annotation.SuppressLint;
import android.support.annotation.NonNull;

import com.github.megatronking.netbare.NetBareLog;
import com.github.megatronking.netbare.ssl.SSLEngineFactory;
import com.github.megatronking.netbare.ssl.SSLResponseCodec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import javax.net.ssl.SSLEngine;

/**
 * Http SSL codec enables Application-Layer Protocol Negotiation(ALPN).
 *
 * See http://tools.ietf.org/html/draft-agl-tls-nextprotoneg-04#page-4
 *
 * @author Megatron King
 * @since 2019/1/3 23:31
 */
/* package */ class SSLHttpResponseCodec extends SSLResponseCodec {

    private SSLEngine mSSLEngine;

    private boolean mAlpnEnabled;
    private boolean mSelectedAlpnResolved;
    private AlpnResolvedCallback mAlpnCallback;

    /* package */ SSLHttpResponseCodec(SSLEngineFactory factory) {
        super(factory);
    }

    @Override
    protected SSLEngine createEngine(SSLEngineFactory factory) {
        if (mSSLEngine == null) {
            mSSLEngine = super.createEngine(factory);
            if (mSSLEngine != null) {
                enableAlpn();
            }
        }
        return mSSLEngine;
    }

    @Override
    public void decode(ByteBuffer buffer, @NonNull CodecCallback callback) throws IOException {
        super.decode(buffer, callback);
        // ALPN is put in ServerHello, once we receive the remote server packet, the ALPN must be
        // resolved.
        if (mAlpnCallback != null && !mSelectedAlpnResolved) {
            mAlpnCallback.onResult(getAlpnSelectedProtocol());
        }
        mSelectedAlpnResolved = true;
    }

    public void prepareHandshake(AlpnResolvedCallback callback) throws IOException {
        this.mAlpnCallback = callback;
        super.prepareHandshake();
    }

    @SuppressLint("PrivateApi")
    private String getAlpnSelectedProtocol() {
        if (!mAlpnEnabled) {
            return null;
        }
        byte[] alpnResult = null;
        try {
            Class<?> nativeCryptoClass = Class.forName("com.android.org.conscrypt.NativeCrypto");
            Method SSL_get0_alpn_selectedMethod = nativeCryptoClass.getDeclaredMethod(
                    "SSL_get0_alpn_selected", long.class);
            SSL_get0_alpn_selectedMethod.setAccessible(true);

            Field sslNativePointerField = mSSLEngine.getClass().getDeclaredField("sslNativePointer");
            sslNativePointerField.setAccessible(true);
            long sslNativePointer = (long) sslNativePointerField.get(mSSLEngine);
            alpnResult = (byte[]) SSL_get0_alpn_selectedMethod.invoke(null, sslNativePointer);
        } catch (ClassNotFoundException | NoSuchMethodException | NoSuchFieldException
                | IllegalAccessException | InvocationTargetException e) {
            NetBareLog.e(e.getMessage());
        }
        return alpnResult != null ? new String(alpnResult, Charset.forName("UTF-8")) : null;
    }

    private void enableAlpn() {
        try {
            Field sslParametersField = mSSLEngine.getClass().getDeclaredField("sslParameters");
            sslParametersField.setAccessible(true);
            Object sslParameters = sslParametersField.get(mSSLEngine);
            if (sslParameters != null) {
                Field useSessionTicketsField = sslParameters.getClass().getDeclaredField("useSessionTickets");
                useSessionTicketsField.setAccessible(true);
                useSessionTicketsField.set(sslParameters, true);
                Field useSniField = sslParameters.getClass().getDeclaredField("useSni");
                useSniField.setAccessible(true);
                useSniField.set(sslParameters, true);
                Field alpnProtocolsField = sslParameters.getClass().getDeclaredField("alpnProtocols");
                alpnProtocolsField.setAccessible(true);
                alpnProtocolsField.set(sslParameters, concatLengthPrefixed(HttpProtocol.HTTP_1_1,
                        HttpProtocol.HTTP_2));
                mAlpnEnabled = true;
            }
        } catch (NoSuchFieldException | IllegalAccessException e) {
            NetBareLog.e(e.getMessage());
        }
    }

    private byte[] concatLengthPrefixed(HttpProtocol ... protocols) {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        for (HttpProtocol protocol : protocols) {
            String protocolStr = protocol.toString();
            os.write(protocolStr.length());
            os.write(protocolStr.getBytes(Charset.forName("UTF-8")), 0, protocolStr.length());
        }
        return os.toByteArray();
    }

    interface AlpnResolvedCallback {

        void onResult(String selectedAlpnProtocol) throws IOException;

    }

}

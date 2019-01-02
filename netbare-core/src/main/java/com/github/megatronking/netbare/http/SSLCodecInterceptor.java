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

import android.support.annotation.NonNull;

import com.github.megatronking.netbare.NetBareLog;
import com.github.megatronking.netbare.gateway.Request;
import com.github.megatronking.netbare.gateway.Response;
import com.github.megatronking.netbare.ssl.JKS;
import com.github.megatronking.netbare.ssl.SSLCodec;
import com.github.megatronking.netbare.ssl.SSLEngineFactory;
import com.github.megatronking.netbare.ssl.SSLRequestCodec;
import com.github.megatronking.netbare.ssl.SSLResponseCodec;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/**
 * An interceptor decodes SSL encrypt packets to plaintext packets.
 *
 * @author Megatron King
 * @since 2018-11-15 15:39
 */
/* package */ class SSLCodecInterceptor extends HttpPendingInterceptor implements SSLRefluxCallback {

    private static SSLEngineFactory sEngineFactory;

    private Request mRequest;
    private Response mResponse;

    private JKS mJKS;

    private SSLRequestCodec mRequestCodec;
    private SSLResponseCodec mResponseCodec;

    /* package */ SSLCodecInterceptor(JKS jks, Request request, Response response) {
        this.mJKS = jks;
        this.mRequest = request;
        this.mResponse = response;

        if (sEngineFactory == null) {
            try {
                sEngineFactory = new SSLEngineFactory(jks);
            } catch (GeneralSecurityException | IOException e) {
                NetBareLog.e("Create SSLEngineFactory failed: " + e.getMessage());
            }
        }

        mRequestCodec = new SSLRequestCodec(sEngineFactory);
        mResponseCodec = new SSLResponseCodec(sEngineFactory);
    }

    @Override
    protected void intercept(@NonNull final HttpRequestChain chain, @NonNull ByteBuffer buffer)
            throws IOException {
        if (!chain.request().isHttps()) {
            chain.process(buffer);
        } else if (!mJKS.isInstalled()) {
            // Skip all interceptors
            chain.processFinal(buffer);
            NetBareLog.w("JSK not installed, skip all interceptors!");
        } else {
            mRequestCodec.setRequest(chain.request());
            // Merge buffers
            mRequestCodec.decode(mergeRequestBuffer(buffer),
                    new SSLCodec.CodecCallback() {
                @Override
                public void onPending(ByteBuffer buffer) {
                    buffer.slice();
                    pendRequestBuffer(buffer);
                }

                @Override
                public void onProcess(ByteBuffer buffer) throws IOException {
                    chain.processFinal(buffer);
                }

                @Override
                public void onEncrypt(ByteBuffer buffer) throws IOException {
                    mResponse.process(buffer);
                }

                @Override
                public void onDecrypt(ByteBuffer buffer) throws IOException {
                    chain.process(buffer);
                }
            });

            // Prepare handshake with remote server
            mResponseCodec.setRequest(chain.request());
            mResponseCodec.prepareHandshake();
        }
    }

    @Override
    protected void intercept(@NonNull final HttpResponseChain chain, @NonNull ByteBuffer buffer)
            throws IOException {
        if (!chain.response().isHttps()) {
            chain.process(buffer);
        } else if (!mJKS.isInstalled()) {
            // Skip all interceptors
            chain.processFinal(buffer);
            NetBareLog.w("JSK not installed, skip all interceptors!");
        } else {
            // Merge buffers
            mResponseCodec.decode(mergeResponseBuffer(buffer),
                    new SSLCodec.CodecCallback() {
                        @Override
                        public void onPending(ByteBuffer buffer) {
                            buffer.slice();
                            pendResponseBuffer(buffer);
                        }

                        @Override
                        public void onProcess(ByteBuffer buffer) throws IOException {
                            chain.processFinal(buffer);
                        }

                        @Override
                        public void onEncrypt(ByteBuffer buffer) throws IOException {
                            mRequest.process(buffer);
                        }

                        @Override
                        public void onDecrypt(ByteBuffer buffer) throws IOException {
                            chain.process(buffer);
                        }

                    });
        }
    }

    @Override
    public void onRequest(HttpRequest request, ByteBuffer buffer) throws IOException {
        mResponseCodec.encode(buffer, new SSLCodec.CodecCallback() {
            @Override
            public void onPending(ByteBuffer buffer) {
            }

            @Override
            public void onProcess(ByteBuffer buffer) {
            }

            @Override
            public void onEncrypt(ByteBuffer buffer) throws IOException {
                // The encrypt request data is sent to remote server
                mRequest.process(buffer);
            }

            @Override
            public void onDecrypt(ByteBuffer buffer) {
            }
        });
    }

    @Override
    public void onResponse(HttpResponse response, ByteBuffer buffer) throws IOException {
        buffer.slice();
        mRequestCodec.encode(buffer, new SSLCodec.CodecCallback() {
            @Override
            public void onPending(ByteBuffer buffer) {
            }

            @Override
            public void onProcess(ByteBuffer buffer) {
            }

            @Override
            public void onEncrypt(ByteBuffer buffer) throws IOException {
                // The encrypt response data is sent to proxy server
                mResponse.process(buffer);
            }

            @Override
            public void onDecrypt(ByteBuffer buffer) {
            }
        });
    }

}

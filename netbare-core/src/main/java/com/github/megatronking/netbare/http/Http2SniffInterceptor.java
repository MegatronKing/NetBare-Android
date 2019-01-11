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

import com.github.megatronking.netbare.http2.Http2;
import com.google.common.primitives.Bytes;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Verifies the HTTP packet and determines whether it is a HTTP2 protocol packets.
 *
 * @author Megatron King
 * @since 2019/1/5 14:02
 */
/* package */ class Http2SniffInterceptor extends HttpIndexInterceptor {

    /* package */ private SSLRefluxCallback mCallback;

    /* package */ Http2SniffInterceptor(SSLRefluxCallback callback) {
        this.mCallback = callback;
    }

    @Override
    protected void intercept(@NonNull HttpRequestChain chain, @NonNull ByteBuffer buffer, int index) throws IOException {
        if (index == 0) {
            // HTTP2 is forces to use SSL connection.
            if (chain.request().isHttps()) {
                if (buffer.hasRemaining() && Bytes.indexOf(buffer.array(),
                        Http2.CONNECTION_PREFACE) == buffer.position()) {
                    chain.request().session().protocol = HttpProtocol.HTTP_2;
                    // Skip preface frame data.
                    mCallback.onRequest(chain.request(), buffer);
                    return;
                }
            }
        }
        if (buffer.hasRemaining()) {
            chain.process(buffer);
        }
    }

    @Override
    protected void intercept(@NonNull HttpResponseChain chain, @NonNull ByteBuffer buffer, int index) throws IOException {
        chain.process(buffer);
    }

}

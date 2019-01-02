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

import com.github.megatronking.netbare.NetBareXLog;
import com.github.megatronking.netbare.ip.Protocol;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * If a HTTP connection is keep-alive or Http2.0, there will be multiple sessions go through the
 * same virtual gateway. Those sessions are saw as one and not distinguished, this will increase
 * the difficulty of interception. We use this interceptor to separate them into independent
 * sessions and intercept them one by one.
 *
 * @author Megatron King
 * @since 2018-12-15 15:17
 */
/* package */ class HttpMultiRequestsInterceptor extends HttpInterceptor {

    private HttpVirtualGateway mGateway;

    private HttpResponse mCurrentResponse;

    private NetBareXLog mLog;

    /* package */ HttpMultiRequestsInterceptor(HttpVirtualGateway gateway) {
        this.mGateway = gateway;
    }

    @Override
    protected void intercept(@NonNull HttpRequestChain chain, @NonNull ByteBuffer buffer)
            throws IOException {
        // Response nonnull means there are multiple requests in one tunnel. It is possible if
        // keep-alive is true.
        if (mCurrentResponse != null) {
            // Rebuild a new session.
            chain.updateRequest(mGateway.newSession());
            mCurrentResponse = null;
            if (mLog == null) {
                mLog = new NetBareXLog(Protocol.TCP, chain.request().ip(), chain.request().port());
            }
            mLog.w("Multi requests are in one connection.");
        }
        chain.process(buffer);
    }

    @Override
    protected void intercept(@NonNull HttpResponseChain chain, @NonNull ByteBuffer buffer)
            throws IOException {
        mCurrentResponse = chain.response();
        chain.process(buffer);
    }

}

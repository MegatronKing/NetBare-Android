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

import com.github.megatronking.netbare.gateway.InterceptorChain;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * Http request chain, responsible for intercepting http request packets.
 *
 * @author Megatron King
 * @since 2018-11-16 23:21
 */
public class HttpRequestChain extends InterceptorChain<HttpRequest, HttpInterceptor> {

    private HttpRequest mRequest;

    /* package */ HttpRequestChain(HttpRequest request, List<HttpInterceptor> interceptors) {
        super(request, interceptors);
        mRequest = request;
    }

    private HttpRequestChain(HttpRequest request, List<HttpInterceptor> interceptors, int index) {
        super(request, interceptors, index);
        mRequest = request;
    }

    @Override
    protected void processNext(ByteBuffer buffer, HttpRequest request,
                               List<HttpInterceptor> interceptors, int index) throws IOException {
        HttpInterceptor interceptor = interceptors.get(index);
        if (interceptor != null) {
            // Use the field member, it would be changed anytime.
            interceptor.intercept(new HttpRequestChain(mRequest, interceptors, ++index), buffer);
        }
    }

    @NonNull
    public HttpRequest request() {
        return mRequest;
    }

    /* package */ void updateRequest(HttpRequest request) {
        this.mRequest = request;
    }

}

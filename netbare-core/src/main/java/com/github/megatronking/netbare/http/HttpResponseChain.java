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

import androidx.annotation.NonNull;

import com.github.megatronking.netbare.gateway.AbstractResponseChain;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * Http response chain, responsible for intercepting http response packets.
 *
 * @author Megatron King
 * @since 2018-11-16 23:21
 */
public class HttpResponseChain extends AbstractResponseChain<HttpResponse, HttpInterceptor> {

    private HttpZygoteResponse mZygoteResponse;

    /* package */ HttpResponseChain(HttpZygoteResponse response, List<HttpInterceptor> interceptors) {
        this(response, interceptors, 0, null);
    }

    /* package */ HttpResponseChain(HttpZygoteResponse response, List<HttpInterceptor> interceptors,
                                    int index, Object tag) {
        super(response, interceptors, index, tag);
        this.mZygoteResponse = response;
    }

    HttpZygoteResponse zygoteResponse() {
        return mZygoteResponse;
    }

    @Override
    protected void processNext(ByteBuffer buffer, HttpResponse response,
                               List<HttpInterceptor> interceptors, int index, Object tag) throws IOException {
        HttpInterceptor interceptor = interceptors.get(index);
        if (interceptor != null) {
            interceptor.intercept(new HttpResponseChain(mZygoteResponse, interceptors, ++index, tag), buffer);
        }
    }

    @Override
    @NonNull
    public HttpResponse response() {
        HttpResponse active = mZygoteResponse.getActive();
        return active != null ? active : mZygoteResponse;
    }

}

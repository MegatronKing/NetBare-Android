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
package com.github.megatronking.netbare.gateway;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * A response chain, responsible for intercepting response packets.
 *
 * @author Megatron King
 * @since 2018-11-14 23:19
 */
public class ResponseChain extends AbstractResponseChain<Response, Interceptor<Request,
        RequestChain, Response, ResponseChain>> {

    private Response mResponse;

    public ResponseChain(Response response, List<Interceptor<Request, RequestChain,
            Response, ResponseChain>> interceptors) {
        super(response, interceptors);
        mResponse = response;
    }

    private ResponseChain(Response response, List<Interceptor<Request, RequestChain,
            Response, ResponseChain>> interceptors, int index, Object tag) {
        super(response, interceptors, index, tag);
        mResponse = response;
    }

    @Override
    protected void processNext(ByteBuffer buffer, Response response, List<Interceptor<Request, RequestChain,
            Response, ResponseChain>> interceptors,
                               int index, Object tag) throws IOException {
        Interceptor<Request, RequestChain, Response, ResponseChain> interceptor = interceptors.get(index);
        if (interceptor != null) {
            interceptor.intercept(new ResponseChain(response, interceptors, ++index, tag), buffer);
        }
    }

    @Override
    @NonNull
    public Response response() {
        return mResponse;
    }

}

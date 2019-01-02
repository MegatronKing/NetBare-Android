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

import com.github.megatronking.netbare.gateway.Request;
import com.github.megatronking.netbare.gateway.Response;
import com.github.megatronking.netbare.gateway.SpecVirtualGateway;
import com.github.megatronking.netbare.gateway.VirtualGateway;
import com.github.megatronking.netbare.ip.Protocol;
import com.github.megatronking.netbare.net.Session;
import com.github.megatronking.netbare.ssl.JKS;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * A {@link VirtualGateway} that is responsible for HTTP(S) packets interception. It integrates
 * several internal {@link HttpInterceptor}s to decode and parse HTTP(S) packets. And also it
 * supports extensional {@link HttpInterceptor}s. Use {@link HttpVirtualGatewayFactory} to
 * create an instance.
 *
 * @author Megatron King
 * @since 2018-11-20 23:43
 */
/* package */ class HttpVirtualGateway extends SpecVirtualGateway {

    private HttpRequest mHttpRequest;
    private HttpResponse mHttpResponse;

    private List<HttpInterceptor> mInterceptors;

    /* package */ HttpVirtualGateway(Session session, Request request, Response response, JKS jks,
                                     List<HttpInterceptorFactory> factories) {
        super(Protocol.TCP, session, request, response);

        this.mInterceptors = new ArrayList<>(factories.size() + 5);
        for (HttpInterceptorFactory factory : factories) {
            mInterceptors.add(factory.create());
        }

        HttpSession httpSession = new HttpSession();
        this.mHttpRequest = new HttpRequest(request, null, httpSession);
        this.mHttpResponse = new HttpResponse(response, null, httpSession);

        // Add default interceptors.
        SSLCodecInterceptor codecInterceptor = new SSLCodecInterceptor(jks, request, response);
        SSLRefluxInterceptor refluxInterceptor = new SSLRefluxInterceptor(codecInterceptor);

        mInterceptors.add(0, new HttpHeaderParseInterceptor());
        mInterceptors.add(0, new HttpHeaderSeparateInterceptor());
        mInterceptors.add(0, new HttpMultiRequestsInterceptor(this));
        mInterceptors.add(0, codecInterceptor);
        mInterceptors.add(0, new HttpSniffInterceptor(httpSession));
        mInterceptors.add(mInterceptors.size(), refluxInterceptor);

        //
        // SSL Flow Model:
        //
        //        Request                                  Response
        //
        //     out        in                             in        out
        //      ⇈         ⇊                               ⇊         ⇈
        //       Encrypted                                 Encrypted
        //      ⇈         ⇊                               ⇊         ⇈
        //   -----------------------------------------------------------
        //  |                     Codec Interceptor                     |
        //   -----------------------------------------------------------
        //      ⇈  |      ⇊              ...              ⇊      |  ⇈
        //         |      ⇊              ...              ⇊      |
        //      ⇈  |  Decrypted  |   interceptors  |  Decrypted  |  ⇈
        //         |      ⇊              ...              ⇊      |
        //      ⇈  |      ⇊              ...              ⇊      |  ⇈
        //   -----------------------------------------------------------
        //  |                     Reflux Interceptor                    |
        //   -----------------------------------------------------------
        //      ⇈ ⇇  ⇇  ⇇ ⇊                               ⇊ ⇉  ⇉  ⇉ ⇈
        //
    }

    @Override
    public void onSpecRequest(ByteBuffer buffer) throws IOException {
        new HttpRequestChain(mHttpRequest, mInterceptors).process(buffer);
    }

    @Override
    public void onSpecResponse(ByteBuffer buffer) throws IOException {
        new HttpResponseChain(mHttpResponse, mInterceptors).process(buffer);
    }

    @Override
    public void onSpecRequestFinished() {
        for (HttpInterceptor interceptor: mInterceptors) {
            interceptor.onRequestFinished(mHttpRequest);
        }
    }

    @Override
    public void onSpecResponseFinished() {
        for (HttpInterceptor interceptor: mInterceptors) {
            interceptor.onResponseFinished(mHttpResponse);
        }
    }

    /* package */ HttpRequest newSession() {
        // Notify the last request and response to finish, it must be started from the current
        // interceptor.
        boolean findReqCurrentInterceptor = false;
        for (HttpInterceptor interceptor: mInterceptors) {
            if (!findReqCurrentInterceptor && interceptor instanceof HttpMultiRequestsInterceptor) {
                findReqCurrentInterceptor = true;
            }
            if (findReqCurrentInterceptor) {
                interceptor.onRequestFinished(mHttpRequest);
            }
        }
        boolean findResCurrentInterceptor = false;
        for (HttpInterceptor interceptor: mInterceptors) {
            if (!findResCurrentInterceptor && interceptor instanceof HttpMultiRequestsInterceptor) {
                findResCurrentInterceptor = true;
            }
            if (findResCurrentInterceptor) {
                interceptor.onResponseFinished(mHttpResponse);
            }
        }
        // Rebuild request and response session.
        HttpSession httpSession = new HttpSession();
        // Inherit the http type.
        httpSession.isHttps = mHttpRequest.isHttps();
        // Use a http id to identify the new requests.
        HttpId httpId = new HttpId();
        this.mHttpRequest = new HttpRequest(mRequest, httpId, httpSession);
        this.mHttpResponse = new HttpResponse(mResponse, httpId, httpSession);
        return mHttpRequest;
    }

}

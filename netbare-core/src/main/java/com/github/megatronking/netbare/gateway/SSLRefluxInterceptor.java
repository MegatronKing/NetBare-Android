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

import com.github.megatronking.netbare.ssl.SSLRefluxCallback;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * An interceptor locates at the last layer of the interceptors. It is responsible for send
 * plaintext packets to {@link SSLCodecInterceptor}.
 *
 * @author Megatron King
 * @since 2018-11-15 15:39
 */
public abstract class SSLRefluxInterceptor<Req extends Request, ReqChain extends AbstractRequestChain<Req, ? extends Interceptor>,
        Res extends Response, ResChain extends AbstractResponseChain<Res, ? extends Interceptor>>
        implements Interceptor<Req, ReqChain, Res, ResChain> {

    private SSLRefluxCallback<Req, Res> mRefluxCallback;

    /**
     * Should reflux the request buffer to SSL codec if the buffer is origin decrypted.
     *
     * @param chain The request chain.
     * @return True if needs to encrypt again.
     */
    protected abstract boolean shouldReflux(ReqChain chain);

    /**
     * Should reflux the response buffer to SSL codec if the buffer is origin decrypted.
     *
     * @param chain The response chain.
     * @return True if needs to encrypt again.
     */
    protected abstract boolean shouldReflux(ResChain chain);

    public SSLRefluxInterceptor(SSLRefluxCallback<Req, Res> refluxCallback) {
        this.mRefluxCallback = refluxCallback;
    }

    @Override
    public void intercept(@NonNull ReqChain chain, @NonNull ByteBuffer buffer)
            throws IOException {
        if (shouldReflux(chain)) {
            mRefluxCallback.onRequest(chain.request(), buffer);
        } else {
            chain.process(buffer);
        }
    }

    @Override
    public void intercept(@NonNull ResChain chain, @NonNull ByteBuffer buffer)
            throws IOException {
        if (shouldReflux(chain)) {
            mRefluxCallback.onResponse(chain.response(), buffer);
        } else {
            chain.process(buffer);
        }
    }

    @Override
    public void onRequestFinished(@NonNull Req request) {
    }

    @Override
    public void onResponseFinished(@NonNull Res response) {
    }

}

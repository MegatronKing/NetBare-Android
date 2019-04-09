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

import java.util.List;

/**
 * This is a specific chain for all the requests.
 *
 * @author Megatron King
 * @since 2019/4/6 19:45
 */
public abstract class AbstractRequestChain<Req extends Request, I extends Interceptor>
        extends InterceptorChain<Req, I> {

    /**
     * Get the current request instance in this chain.
     *
     * @return An instance of {@link Request}.
     */
    public abstract Req request();

    /**
     * Constructs an intercept chain for request.
     *
     * @param request A {@link Request} implementation.
     * @param interceptors A collection of interceptors.
     */
    protected AbstractRequestChain(Req request, List<I> interceptors) {
        super(request, interceptors);
    }

    /**
     * Constructs an intercept chain for request.
     *
     * @param request A {@link Request} implementation.
     * @param interceptors A collection of interceptors.
     * @param index The head index.
     * @param tag The chain's tag.
     */
    protected AbstractRequestChain(Req request, List<I> interceptors, int index, Object tag) {
        super(request, interceptors, index, tag);
    }

}

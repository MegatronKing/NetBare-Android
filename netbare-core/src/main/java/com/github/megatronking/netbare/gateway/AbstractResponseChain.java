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
 * This is a specific chain for all the responses.
 *
 * @author Megatron King
 * @since 2019/4/6 19:51
 */
public abstract class AbstractResponseChain<Res extends Response, I extends Interceptor>
        extends InterceptorChain<Res, I> {

    /**
     * Get the current response instance in this chain.
     *
     * @return An instance of {@link Response}.
     */
    public abstract Res response();

    /**
     * Constructs an intercept chain for response.
     *
     * @param response A {@link Response} implementation.
     * @param interceptors A collection of interceptors.
     */
    protected AbstractResponseChain(Res response, List<I> interceptors) {
        super(response, interceptors);
    }

    /**
     * Constructs an intercept chain for response.
     *
     * @param response A {@link Response} implementation.
     * @param interceptors A collection of interceptors.
     * @param index The head index.
     * @param tag The chain's tag.
     */
    protected AbstractResponseChain(Res response, List<I> interceptors, int index, Object tag) {
        super(response, interceptors, index, tag);
    }

}

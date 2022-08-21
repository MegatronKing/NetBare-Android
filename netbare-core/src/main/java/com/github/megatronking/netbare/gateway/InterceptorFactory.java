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

/**
 * Factory used by developer to create their own interceptor for virtual gateway.
 *
 * @author Megatron King
 * @since 2018-11-02 23:46
 */
public interface InterceptorFactory<Req extends Request, ReqChain extends AbstractRequestChain<Req, ? extends Interceptor>,
        Res extends Response, ResChain extends AbstractResponseChain<Res, ? extends Interceptor>> {

    /**
     * Creates an interceptor instance and immediately returns it, it must not be null.
     *
     * @return A newly created interceptor.
     */
    @NonNull
    Interceptor<Req, ReqChain, Res, ResChain> create();

}

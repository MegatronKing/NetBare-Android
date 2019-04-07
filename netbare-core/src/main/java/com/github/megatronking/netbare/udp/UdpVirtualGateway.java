/*
 *  NetBare - An android network capture and injection library.
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
package com.github.megatronking.netbare.udp;

import com.github.megatronking.netbare.gateway.Request;
import com.github.megatronking.netbare.gateway.Response;
import com.github.megatronking.netbare.gateway.SpecVirtualGateway;
import com.github.megatronking.netbare.gateway.VirtualGateway;
import com.github.megatronking.netbare.ip.Protocol;
import com.github.megatronking.netbare.net.Session;

/**
 * A {@link VirtualGateway} that is responsible for UDP protocol packets interception.
 *
 * @author Megatron King
 * @since 2019-04-06 17:03
 */
public abstract class UdpVirtualGateway extends SpecVirtualGateway {

    public UdpVirtualGateway(Session session, Request request, Response response) {
        super(Protocol.UDP, session, request, response);
    }

}

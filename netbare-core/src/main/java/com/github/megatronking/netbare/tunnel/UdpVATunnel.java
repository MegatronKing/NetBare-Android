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
/*
 * Copyright (C) 2013 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.megatronking.netbare.tunnel;

import com.github.megatronking.netbare.NetBareLog;
import com.github.megatronking.netbare.NetBareVirtualGateway;
import com.github.megatronking.netbare.gateway.Request;
import com.github.megatronking.netbare.gateway.Response;
import com.github.megatronking.netbare.gateway.VirtualGateway;
import com.github.megatronking.netbare.net.Session;
import com.github.megatronking.netbare.ip.packet.UdpPacket;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

/**
 * UDP protocol virtual gateway tunnel wraps {@link UdpRemoteTunnel} and itself as client and
 * server.
 *
 * @author Megatron King
 * @since 2018-11-25 20:16
 */
public class UdpVATunnel extends VirtualGatewayTunnel implements NioCallback,
        Tunnel {

    private final NioTunnel mRemoteTunnel;
    private final FileOutputStream mOutput;

    private final int mMtu;

    private Session mSession;
    private VirtualGateway mGateway;

    private UdpPacket templatePacket;

    public UdpVATunnel(Session session, NioTunnel tunnel, FileOutputStream output, int mtu) {
        this.mRemoteTunnel = tunnel;
        this.mOutput = output;
        this.mMtu = mtu;

        this.mSession = session;
        this.mGateway = new NetBareVirtualGateway(session,
                new Request(mRemoteTunnel), new Response(this));

        this.mRemoteTunnel.setNioCallback(this);
    }

    @Override
    public void connect(InetSocketAddress address) throws IOException {
        mRemoteTunnel.connect(address);
    }

    @Override
    public VirtualGateway getGateway() {
        return mGateway;
    }

    @Override
    public void onConnected() {
    }

    @Override
    public void onRead() throws IOException {
        if (mRemoteTunnel.isClosed()) {
            mGateway.onRequestFinished();
            mGateway.onResponseFinished();
            return;
        }
        ByteBuffer buffer = ByteBuffer.allocate(mMtu);
        int len;
        try {
            len = mRemoteTunnel.read(buffer);
        } catch (IOException e) {
            throw new ConnectionShutdownException(e.getMessage());
        }
        if (len < 0) {
            close();
            return;
        }
        mGateway.onResponse(buffer);
    }

    @Override
    public void onWrite() {
    }

	@Override
	public void onClosed() {
    	try {
			close();
		} catch (IOException e) {
    		NetBareLog.wtf(e);
		}
	}

    @Override
    public NioTunnel getTunnel() {
        return null;
    }

    @Override
    public void close() throws IOException{
        mRemoteTunnel.close();
        mGateway.onRequestFinished();
        mGateway.onResponseFinished();
    }

    public void send(UdpPacket packet) {
        if (mRemoteTunnel.isClosed()) {
            return;
        }
        // Clone a template by the send data.
        if (templatePacket == null) {
            templatePacket = createTemplate(packet);
        }

        try {
            mGateway.onRequest(packet.getData());
        } catch (IOException e) {
            NetBareLog.e(e.getMessage());
			try {
				close();
			} catch (IOException e1) {
				NetBareLog.e(e.getMessage());
			}
        }
    }

    @Override
    public void write(ByteBuffer buffer) throws IOException {
		final short headerLength = templatePacket.getHeaderLength();
        UdpPacket packet = new UdpPacket(ByteBuffer.allocate(
				headerLength & 0xFFFF
						+ buffer.remaining()
		));

        templatePacket.getBuffer().get(packet.getBuffer().array(), 0, headerLength);
        buffer.get(buffer.array(), headerLength, packet.getBuffer().limit() - headerLength & 0xFFFF);

        packet.getIpHeader().setTotalLength((short) packet.getBuffer().limit());

        packet.getUdpHeader().setTotalLength((short) (packet.getBuffer().limit() - packet.getIpHeader().getHeaderLength()));

        packet.updateChecksum();
        mOutput.write(packet.getBuffer().array(), 0, packet.getBuffer().limit());

        mSession.receiveDataSize += packet.getBuffer().limit();
    }

    public NioTunnel getRemoteChannel() {
        return mRemoteTunnel;
    }

    private UdpPacket createTemplate(UdpPacket packet) {
    	UdpPacket templatePacket = new UdpPacket(ByteBuffer.allocate(packet.getHeaderLength() & 0xFFFF));
    	packet.getBuffer().get(templatePacket.getBuffer().array(), 0, templatePacket.getHeaderLength() & 0xFFFF);
        // Swap ip
        templatePacket.getIpHeader().setSourceIp(packet.getIpHeader().getDestinationIp());
        templatePacket.getIpHeader().setDestinationIp(packet.getIpHeader().getSourceIp());
        // Swap port
		templatePacket.getUdpHeader().setDestinationPort(packet.getUdpHeader().getDestinationPort());
		templatePacket.getUdpHeader().setSourcePort(packet.getUdpHeader().getSourcePort());
        return templatePacket;
    }

}

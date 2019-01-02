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
package com.github.megatronking.netbare.tunnel;

import com.github.megatronking.netbare.NetBareUtils;
import com.github.megatronking.netbare.gateway.VirtualGateway;
import com.github.megatronking.netbare.NetBareVirtualGateway;
import com.github.megatronking.netbare.gateway.Request;
import com.github.megatronking.netbare.gateway.Response;
import com.github.megatronking.netbare.net.Session;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * TCP protocol virtual gateway tunnel wraps {@link TcpProxyTunnel} and {@link TcpRemoteTunnel} as
 * client and server.
 *
 * @author Megatron King
 * @since 2018-11-18 00:19
 */
public class TcpVATunnel extends VirtualGatewayTunnel {

    private final NioTunnel mRemoteTunnel;
    private final NioTunnel mProxyTunnel;
    private VirtualGateway mGateway;

    private final int mMtu;

    private final List<ByteBuffer> mProxyBuffers;
    private final List<ByteBuffer> mRemoteBuffers;

    private boolean isProxyWritable;
    private boolean isRemoteWritable;

    public TcpVATunnel(Session session, NioTunnel proxyServerTunnel, NioTunnel remoteServerTunnel, int mtu) {
        this.mProxyTunnel = proxyServerTunnel;
        this.mRemoteTunnel = remoteServerTunnel;
        this.mGateway = new NetBareVirtualGateway(session, new Request(mRemoteTunnel),
                new Response(mProxyTunnel));

        this.mMtu = mtu;

        this.mProxyBuffers = new ArrayList<>();
        this.mRemoteBuffers = new ArrayList<>();

        setCallbacks();
    }

    @Override
    public VirtualGateway getGateway() {
        return mGateway;
    }

    @Override
    public void connect(InetSocketAddress address) throws IOException {
        mRemoteTunnel.connect(address);
    }

    private void setCallbacks() {
        mProxyTunnel.setNioCallback(new NioCallback() {
            @Override
            public void onConnected() {
                // Nothing to do.
            }

            @Override
            public void onRead() throws IOException {
                if (mProxyTunnel.isClosed()) {
                    mGateway.sendResponseFinished();
                    return;
                }
                ByteBuffer buffer = ByteBuffer.allocate(mMtu);
                int len;
                try {
                    len = mProxyTunnel.read(buffer);
                } catch (IOException e) {
                    throw new ConnectionShutdownException(e.getMessage());
                }
                if (len < 0 || mRemoteTunnel.isClosed()) {
                    NetBareUtils.closeQuietly(mProxyTunnel);
                    mGateway.sendResponseFinished();
                    return;
                }
                if (isRemoteWritable) {
                    mGateway.sendRequest(buffer);
                } else {
                    mRemoteBuffers.add(buffer);
                }
            }

            @Override
            public void onWrite() throws IOException {
                isProxyWritable = true;
                for(ByteBuffer buffer : mProxyBuffers) {
                    mGateway.sendResponse(buffer);
                }
                mProxyBuffers.clear();
            }

            @Override
            public void onClosed() {
                close();
            }

            @Override
            public NioTunnel getTunnel() {
                return null;
            }
        });
        mRemoteTunnel.setNioCallback(new NioCallback() {
            @Override
            public void onConnected() throws IOException {
                // Prepare to read data.
                mRemoteTunnel.prepareReadWrite();
                mProxyTunnel.prepareReadWrite();
            }

            @Override
            public void onRead() throws IOException {
                if (mRemoteTunnel.isClosed()) {
                    mGateway.sendRequestFinished();
                    return;
                }
                ByteBuffer buffer = ByteBuffer.allocate(mMtu);
                int len;
                try {
                    len = mRemoteTunnel.read(buffer);
                } catch (IOException e) {
                    throw new ConnectionShutdownException(e.getMessage());
                }
                if (len < 0 || mProxyTunnel.isClosed()) {
                    NetBareUtils.closeQuietly(mRemoteTunnel);
                    mGateway.sendRequestFinished();
                    return;
                }
                if (isProxyWritable) {
                    mGateway.sendResponse(buffer);
                } else {
                    mProxyBuffers.add(buffer);
                }
            }

            @Override
            public void onWrite() throws IOException {
                isRemoteWritable = true;
                for(ByteBuffer buffer : mRemoteBuffers) {
                    mGateway.sendRequest(buffer);
                }
                mRemoteBuffers.clear();
            }

            @Override
            public void onClosed() {
                close();
            }

            @Override
            public NioTunnel getTunnel() {
                return null;
            }

        });
    }

    @Override
    public void close() {
        NetBareUtils.closeQuietly(mProxyTunnel);
        NetBareUtils.closeQuietly(mRemoteTunnel);
        mGateway.sendRequestFinished();
        mGateway.sendResponseFinished();
    }

}

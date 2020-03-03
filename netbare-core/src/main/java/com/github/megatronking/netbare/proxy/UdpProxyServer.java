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
package com.github.megatronking.netbare.proxy;

import android.net.VpnService;
import android.os.SystemClock;

import com.github.megatronking.netbare.NetBareLog;
import com.github.megatronking.netbare.NetBareUtils;
import com.github.megatronking.netbare.gateway.VirtualGateway;
import com.github.megatronking.netbare.ip.Protocol;
import com.github.megatronking.netbare.net.Session;
import com.github.megatronking.netbare.net.SessionProvider;
import com.github.megatronking.netbare.ip.packet.UdpPacket;
import com.github.megatronking.netbare.tunnel.NioCallback;
import com.github.megatronking.netbare.tunnel.NioTunnel;
import com.github.megatronking.netbare.tunnel.Tunnel;
import com.github.megatronking.netbare.tunnel.UdpRemoteTunnel;
import com.github.megatronking.netbare.tunnel.UdpVATunnel;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The UDP proxy server is a virtual server, every packet from {@link UdpProxyServerForwarder} is
 * saw as a connection. It use {@link UdpVATunnel} to bind {@link VirtualGateway} and
 * {@link NioTunnel} together. Not like TCP, UDP only use {@link UdpRemoteTunnel} to communicate with
 * real remote server.
 *
 * @author Megatron King
 * @since 2018-10-11 17:35
 */
public class UdpProxyServer extends ProxyServer {

    private static final int SELECTOR_WAIT_TIME = 50;

    private final Map<Short, UdpVATunnel> tunnels;

    public UdpProxyServer(VpnService vpnService, SessionProvider sessionProvider, short mtu) throws IOException {
    	super(vpnService, sessionProvider, mtu);
        super.setName("UdpProxyServer");

        this.tunnels = new ConcurrentHashMap<>();
    }

    void send(UdpPacket packet, FileOutputStream output) throws IOException {
        short localPort = packet.getUdpHeader().getSourcePort();
        UdpVATunnel tunnel = tunnels.get(localPort);
        try {
            if (tunnel == null) {
                Session session = getSessionProvider().query(localPort);
                if (session == null) {
                    throw new IOException("No session saved with key: " + localPort);
                }
                NioTunnel remoteTunnel = new UdpRemoteTunnel(getVpnService(), DatagramChannel.open(),
                        getSelector(), session.remoteIp, session.remotePort);
                tunnel = new UdpVATunnel(session, remoteTunnel, output, getMtu());
                tunnel.connect(new InetSocketAddress(packet.getIpHeader().getDestinationIp(),
                        NetBareUtils.convertPort(packet.getUdpHeader().getDestinationPort())));
                tunnels.put(packet.getUdpHeader().getSourcePort(), tunnel);
            }
            tunnel.send(packet);
        } catch (IOException e) {
            tunnels.remove(localPort);
            NetBareUtils.closeQuietly(tunnel);
            throw e;
        }
    }

    @Override
    public void run() {
        NetBareLog.i("[UDP]Server starts running.");
        super.run();
        NetBareUtils.closeQuietly(getSelector());
        NetBareLog.i("[UDP]Server stops running.");
    }

    @Override
    protected void process() throws IOException {
        int select = getSelector().select();
        if (select == 0) {
            // Wait a short time to let the selector register or interest.
            SystemClock.sleep(SELECTOR_WAIT_TIME);
            return;
        }
        Set<SelectionKey> selectedKeys = getSelector().selectedKeys();
        if (selectedKeys == null) {
            return;
        }
        Iterator<SelectionKey> iterator = selectedKeys.iterator();
        while (iterator.hasNext()) {
            SelectionKey key = iterator.next();
            if (key.isValid()) {
                Object attachment = key.attachment();
                if (attachment instanceof NioCallback) {
                    NioCallback callback = (NioCallback) attachment;
                    try {
                        if (key.isReadable()) {
                            callback.onRead();
                        } else if (key.isWritable()) {
                            callback.onWrite();
                        } else if (key.isConnectable()) {
                            callback.onConnected();
                        }
                    } catch (IOException e) {
                        callback.onClosed();
                        removeTunnel(callback.getTunnel());
                    }
                }
            }
            iterator.remove();
        }
    }

	@Override
	public void interrupt() {
		for (UdpVATunnel tunnel : tunnels.values()) {
			NetBareUtils.closeQuietly(tunnel);
		}
		super.interrupt();
	}

    private void removeTunnel(Tunnel tunnel) {
        Map<Short, UdpVATunnel> tunnels = new HashMap<>(this.tunnels);
        for (short key : tunnels.keySet()) {
            if (tunnels.get(key).getRemoteChannel() == tunnel) {
                this.tunnels.remove(key);
            }
        }
    }

	@Override
	public void forward(ByteBuffer buffer, int len, FileOutputStream output) {
		UdpPacket packet = new UdpPacket(buffer);

		// Src IP & Port
		InetAddress localIp = packet.getIpHeader().getSourceIp();
		short localPort = packet.getUdpHeader().getSourcePort();

		// Dest IP & Port
		InetAddress remoteIp = packet.getIpHeader().getDestinationIp();
		short remotePort = packet.getUdpHeader().getDestinationPort();

		// UDP data size
		short udpDataSize = (short) (packet.getIpHeader().getDataLength() & 0xFFFF - packet.getUdpHeader().getHeaderLength());

		NetBareLog.v("ip: %s:%d -> %s:%d", localIp.getHostAddress(),
				NetBareUtils.convertPort(localPort), remoteIp.getHostAddress(),
				NetBareUtils.convertPort(remotePort));
		NetBareLog.v("udp: %s, size: %d", packet.getUdpHeader().toString(), udpDataSize & 0xFFFF);

		Session session = getSessionProvider().ensureQuery(Protocol.UDP, localPort, remotePort, remoteIp);
		session.packetIndex++;

		try {
			send(packet, output);
			session.sendDataSize += udpDataSize & 0xFFFF;
		} catch (IOException e) {
			NetBareLog.e(e.getMessage());
		}
	}

}

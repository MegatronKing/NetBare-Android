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

import com.github.megatronking.netbare.NetBareLog;
import com.github.megatronking.netbare.NetBareUtils;
import com.github.megatronking.netbare.gateway.VirtualGateway;
import com.github.megatronking.netbare.ip.header.IpHeader;
import com.github.megatronking.netbare.ip.Protocol;
import com.github.megatronking.netbare.ip.header.TcpHeader;
import com.github.megatronking.netbare.net.Session;
import com.github.megatronking.netbare.net.SessionProvider;
import com.github.megatronking.netbare.ssl.SSLWhiteList;
import com.github.megatronking.netbare.tunnel.ConnectionShutdownException;
import com.github.megatronking.netbare.tunnel.NioCallback;
import com.github.megatronking.netbare.tunnel.NioTunnel;
import com.github.megatronking.netbare.tunnel.TcpProxyTunnel;
import com.github.megatronking.netbare.tunnel.TcpRemoteTunnel;
import com.github.megatronking.netbare.tunnel.TcpTunnel;
import com.github.megatronking.netbare.tunnel.TcpVATunnel;

import java.io.EOFException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Set;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;

/**
 * The TCP proxy server is a nio {@link ServerSocketChannel}, it listens the connections from
 * {@link VpnService} and forwards request packets to real remote server. This server uses
 * {@link TcpVATunnel} to bind {@link VirtualGateway} and {@link NioTunnel} together. Every TCP
 * connection has two channels: {@link TcpProxyTunnel} and {@link TcpRemoteTunnel}.
 * The {@link TcpProxyTunnel} is responsible for sending remote server response packets to VPN
 * service, and the {@link TcpRemoteTunnel} is responsible for communicating with remote server.
 *
 * @author Megatron King
 * @since 2018-10-11 17:35
 */
public class TcpProxyServer extends ProxyServer {
    private final ServerSocketChannel serverSocketChannel;

    private InetAddress ip;
    private short port;

    public TcpProxyServer(VpnService vpnService, SessionProvider sessionProvider, InetAddress ip, short mtu) throws IOException {
    	super(vpnService, sessionProvider, mtu);
		setName("TcpProxyServer");
		
        this.serverSocketChannel = ServerSocketChannel.open();
        this.serverSocketChannel.configureBlocking(false);
        this.serverSocketChannel.socket().bind(new InetSocketAddress(0));
        this.serverSocketChannel.register(getSelector(), SelectionKey.OP_ACCEPT);

        this.ip = ip;
        this.port = (short) serverSocketChannel.socket().getLocalPort();

        NetBareLog.v("[TCP]proxy server: %s:%d", ip, NetBareUtils.convertPort(port));
    }
    
    public InetAddress getAddress() {
        return ip;
    }
    
    public short getPort() {
        return port;
    }

    @Override
    public void run() {
        NetBareLog.i("[TCP]Server starts running.");
        super.run();
        NetBareUtils.closeQuietly(serverSocketChannel);
        NetBareLog.i("[TCP]Server stops running.");
    }

    @Override
    protected void process() throws IOException {
        int select = getSelector().select();
        if (select == 0) {
            return;
        }
        Set<SelectionKey> selectedKeys = getSelector().selectedKeys();
        if (selectedKeys == null) {
            return;
        }
        Iterator<SelectionKey> iterator = selectedKeys.iterator();
        while (iterator.hasNext()) {
            SelectionKey key = iterator.next();
            try {
                if (key.isValid()) {
                    if (key.isAcceptable()) {
                        onAccept();
                    } else {
                        Object attachment = key.attachment();
                        if (attachment instanceof NioCallback) {
                            NioCallback callback = (NioCallback) attachment;
                            try {
                                if (key.isConnectable()) {
                                    callback.onConnected();
                                } else if (key.isReadable()) {
                                    callback.onRead();
                                } else if (key.isWritable()) {
                                    callback.onWrite();
                                }
                            } catch (IOException e) {
                                NioTunnel tunnel = callback.getTunnel();
                                String ip = null;
                                InetAddress address = ((Socket)tunnel.socket()).getInetAddress();
                                if (address != null) {
                                    ip = address.getHostAddress();
                                }
                                if (!tunnel.isClosed()) {
                                    handleException(e, ip);
                                }
                                callback.onClosed();
                            }
                        }
                    }
                }
            } finally {
                iterator.remove();
            }

        }
    }

    private void onAccept() throws IOException {
        SocketChannel clientChannel = serverSocketChannel.accept();
        Socket clientSocket = clientChannel.socket();

        // The client ip is the remote server ip
        // The client port is the local port(it is the vpn port not the proxy server port)
        String ip = clientSocket.getInetAddress().getHostAddress();
        int port = clientSocket.getPort();

        // The session should have be saved before the tcp packets be forwarded to proxy server. So
        // we can query it by client port.
        Session session = getSessionProvider().query((short) port);
        if (session == null) {
            throw new IOException("No session saved with key: " + port);
        }

        int remotePort = NetBareUtils.convertPort(session.remotePort);

        // Connect remote server and dispatch data.
        TcpTunnel proxyTunnel = null;
        TcpTunnel remoteTunnel = null;
        try {
            proxyTunnel = new TcpProxyTunnel(clientChannel, getSelector(), remotePort);
            remoteTunnel = new TcpRemoteTunnel(getVpnService(), SocketChannel.open(),
                    getSelector(), ip, remotePort);
            TcpVATunnel gatewayTunnel = new TcpVATunnel(session, proxyTunnel,
                    remoteTunnel, getMtu());
            gatewayTunnel.connect(new InetSocketAddress(ip, remotePort));
        } catch (IOException e){
            NetBareUtils.closeQuietly(proxyTunnel);
            NetBareUtils.closeQuietly(remoteTunnel);
            throw e;
        }
    }

    private void handleException(IOException e, String ip) {
        if (e == null || e.getMessage() == null) {
            return;
        }
        if (e instanceof SSLHandshakeException) {
            // Client doesn't accept the MITM CA certificate.
            NetBareLog.e(e.getMessage());
            if (ip != null) {
                NetBareLog.i("add %s to whitelist", ip);
                SSLWhiteList.add(ip);
            }
        } else if (e instanceof ConnectionShutdownException) {
            // Connection exception, do not mind this.
            NetBareLog.e(e.getMessage());
        } else if (e instanceof ConnectException) {
            // Connection timeout
            NetBareLog.e(e.getMessage());
        } else if (e instanceof SSLException && (e.getCause() instanceof EOFException)) {
            // Connection shutdown manually
            NetBareLog.e(e.getMessage());
        } else {
            NetBareLog.wtf(e);
            if (ip != null) {
                NetBareLog.i("add %s to whitelist", ip);
                SSLWhiteList.add(ip);
            }
        }
    }

	public void forward(ByteBuffer packet, int len, FileOutputStream output) {
		IpHeader ipHeader = new IpHeader(packet, 0);
		TcpHeader tcpHeader = new TcpHeader(packet, ipHeader.getHeaderLength());

		// Src IP & Port
		InetAddress localIp = ipHeader.getSourceIp();
		short localPort = tcpHeader.getSourcePort();

		// Dest IP & Port
		InetAddress remoteIp = ipHeader.getDestinationIp();
		short remotePort = tcpHeader.getDestinationPort();

		// TCP data size
		short tcpDataSize = (short) (ipHeader.getDataLength() & 0xFFFF - tcpHeader.getHeaderLength());

		NetBareLog.v("ip: %s:%d -> %s:%d", localIp.getHostAddress(),
				NetBareUtils.convertPort(localPort), remoteIp.getHostAddress(),
				NetBareUtils.convertPort(remotePort));
		NetBareLog.v("tcp: %s, size: %d", tcpHeader.toString(), tcpDataSize & 0xFFFF);

		// Tcp handshakes and proxy forward flow.

		// Client: 10.1.10.1:40988
		// Server: 182.254.116.117:80
		// Proxy Server: 10.1.10.1:38283

		// 10.1.10.1:40988 -> 182.254.116.117:80 SYN
		// Forward: 182.254.116.117:40988 -> 10.1.10.1:38283 SYN

		// 10.1.10.1:38283 -> 182.254.116.117:40988 SYN+ACK
		// Forward: 182.254.116.117:80 -> 10.1.10.1:40988 SYN+ACK

		// 10.1.10.1:40988 -> 182.254.116.117:80 ACK
		// Forward: 182.254.116.117:80 -> 10.1.10.1:38283 ACK

		if (localPort != getPort()) {
			// Client requests to server
			Session session = getSessionProvider().ensureQuery(Protocol.TCP, localPort, remotePort, remoteIp);
			session.packetIndex++;

			// Forward client request to proxy server.
			ipHeader.setSourceIp(remoteIp);
			ipHeader.setDestinationIp(getAddress());
			tcpHeader.setDestinationPort(getPort());

			ipHeader.updateChecksum();
			tcpHeader.updateChecksum(ipHeader);

			session.sendDataSize += tcpDataSize & 0xFFFF;
		} else {
			// Proxy server responses forward client request.
			Session session = getSessionProvider().query(remotePort);
			if (session == null) {
				NetBareLog.w("No session saved with key: " + remotePort);
				return;
			}
			// Forward proxy server response to client.
			ipHeader.setSourceIp(remoteIp);
			ipHeader.setDestinationIp(getAddress());
			tcpHeader.setSourcePort(session.remotePort);

			ipHeader.updateChecksum();
			tcpHeader.updateChecksum(ipHeader);

			session.receiveDataSize += tcpDataSize & 0xFFFF;
		}

		try {
			output.write(packet.array(), 0, len);
		} catch (IOException e) {
			NetBareLog.e(e.getMessage());
		}
	}
}

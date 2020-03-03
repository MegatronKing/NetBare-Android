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
import com.github.megatronking.netbare.net.SessionProvider;

import java.io.Closeable;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.Selector;

/**
 * A local proxy server receives net packets from VPN and transfer them to the real remote server.
 * Every local proxy server runs separated threads and handle specific IP protocols like TCP, UDP
 * and so on. The server is managed by {@link ProxyServerForwarder}, use {@link #start()} to
 * establish the server and {@link #stop()} to terminate it.
 *
 * @author Megatron King
 * @since 2018-10-10 00:23
 */
public abstract class ProxyServer extends Thread implements Closeable {
	private final VpnService vpnService;

	private Selector selector;

	private SessionProvider sessionProvider;

	private short mtu;

	public ProxyServer(VpnService vpnService, SessionProvider sessionProvider, short mtu) throws IOException{
		this.vpnService = vpnService;
		this.selector = Selector.open();
		this.sessionProvider = sessionProvider;
		this.mtu = mtu;
	}

	protected abstract void process() throws IOException;

	@Override
	public void close() throws IOException {
		getSelector().close();
	}

	@Override
	public void run() {
		while (!isInterrupted()) {
			try {
				process();
			} catch (IOException e) {
				NetBareLog.e(e.getMessage());
			}
		}
	}

	public VpnService getVpnService() {
		return vpnService;
	}

	public Selector getSelector() {
		return selector;
	}

	public SessionProvider getSessionProvider() {
		return sessionProvider;
	}

	public short getMtu() {
		return mtu;
	}

	abstract public void forward(ByteBuffer packet, int len, FileOutputStream output);
}

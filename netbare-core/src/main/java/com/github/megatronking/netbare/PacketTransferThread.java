package com.github.megatronking.netbare;

import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.github.megatronking.netbare.ip.IpAddress;
import com.github.megatronking.netbare.ip.Protocol;
import com.github.megatronking.netbare.ip.header.IpHeader;
import com.github.megatronking.netbare.net.SessionProvider;
import com.github.megatronking.netbare.net.UidDumper;
import com.github.megatronking.netbare.proxy.ProxyServer;
import com.github.megatronking.netbare.proxy.TcpProxyServer;
import com.github.megatronking.netbare.proxy.UdpProxyServer;

import java.io.Closeable;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.Map;

public class PacketTransferThread extends Thread implements Closeable{
	private final NetBareConfig config;
	private final VpnService vpnService;

	private ParcelFileDescriptor vpnDescriptor;
	private ParcelFileDescriptor.AutoCloseInputStream input;
	private ParcelFileDescriptor.AutoCloseOutputStream output;

	private VpnService.Builder builder;

	private final Map<Protocol, ProxyServer> proxyServerRegistry = new LinkedHashMap<>(3);

	private byte[] buffer;

	public PacketTransferThread(VpnService vpnService, NetBareConfig config) {
		super("NetBare");
		setDaemon(true);
		this.vpnService = vpnService;
		this.config = config;

		String localIp = config.address.address;
		UidDumper uidDumper = config.dumpUid ? new UidDumper(localIp, config.uidProvider) : null;
		try {
			// Register all supported protocols here.
			// TCP
			proxyServerRegistry.put(Protocol.TCP, new TcpProxyServer(vpnService, new SessionProvider(uidDumper), InetAddress.getByName(localIp), config.mtu));
			// UDP
			proxyServerRegistry.put(Protocol.UDP, new UdpProxyServer(vpnService, new SessionProvider(uidDumper), config.mtu));
			// ICMP
			//this.mForwarderRegistry.put(Protocol.ICMP, new IcmpProxyServerForwarder());
		} catch (IOException e) {
			NetBareLog.wtf(e);
		}
		buffer = new byte[config.mtu & 0xFFFF];
	}

	public void run() {
		super.run();
		// Notify NetBareListener that the service is started now.
		NetBare.get().notifyServiceStarted();

		establishVpn();

		// Notify NetBareListener that the service is stopped now.
		NetBare.get().notifyServiceStopped();

	}

	@Override
	public void close() throws IOException {
		for (ProxyServer proxyServer : proxyServerRegistry.values()) {
			proxyServer.interrupt();
			proxyServer.close();
		}
		proxyServerRegistry.clear();
		input.close();
		output.close();
		vpnDescriptor.close();
		builder.establish().close();
	}

	private void establishVpn() {
		VpnService.Builder builder = vpnService.new Builder();
		builder.setBlocking(true);
		builder.setMtu(config.mtu & 0xFFFF);
		builder.addAddress(config.address.address, config.address.prefixLength);
		if (config.session != null) {
			builder.setSession(config.session);
		}
		if (config.configureIntent != null) {
			builder.setConfigureIntent(config.configureIntent);
		}
		for (IpAddress ip : config.routes) {
			builder.addRoute(ip.address, ip.prefixLength);
		}
		for (String address : config.dnsServers) {
			builder.addDnsServer(address);
		}
		try {
			for (String packageName : config.allowedApplications) {
				builder.addAllowedApplication(packageName);
			}
			for (String packageName : config.disallowedApplications) {
				builder.addDisallowedApplication(packageName);
			}
			// Add self to allowed list.
			if (!config.allowedApplications.isEmpty()) {
				builder.addAllowedApplication(vpnService.getPackageName());
			}
		} catch (PackageManager.NameNotFoundException e) {
			NetBareLog.wtf(e);
		}
		this.builder = builder;
		vpnDescriptor = builder.establish();
		if (vpnDescriptor == null) {
			return;
		}

		// Open io with the VPN descriptor.
		FileDescriptor descriptor = vpnDescriptor.getFileDescriptor();
		if (descriptor == null) {
			return;
		}
		input = new ParcelFileDescriptor.AutoCloseInputStream(vpnDescriptor);
		output = new ParcelFileDescriptor.AutoCloseOutputStream(vpnDescriptor);

		for (ProxyServer proxyServer : proxyServerRegistry.values()) {
			proxyServer.start();
		}

		try {
			// Read packets from input io and forward them to proxy servers.
			while (!isInterrupted()) {
				transfer(ByteBuffer.wrap(buffer), input.read(buffer), output);
			}
		} catch (IOException e) {
			if (!isInterrupted()) {
				NetBareLog.wtf(e);
			}
		}
	}

	private synchronized void transfer(ByteBuffer packet, int len, FileOutputStream output) {
		if (len < IpHeader.MIN_HEADER_LENGTH) {
			NetBareLog.w("Ip header length " + len + " < " + IpHeader.MIN_HEADER_LENGTH);
			return;
		}
		IpHeader ipHeader = new IpHeader(packet, 0);
		Protocol protocol = Protocol.parse(ipHeader.getProtocol());
		ProxyServer proxyServer = proxyServerRegistry.get(protocol);
		if (proxyServer != null) {
			proxyServer.forward(packet, len, output);
		} else {
			NetBareLog.w("Unknown ip protocol: " + ipHeader.getProtocol());
		}
	}
}

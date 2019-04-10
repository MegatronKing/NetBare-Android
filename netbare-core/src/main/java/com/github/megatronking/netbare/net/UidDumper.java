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
package com.github.megatronking.netbare.net;

import android.text.TextUtils;
import android.util.ArrayMap;

import com.github.megatronking.netbare.NetBareConfig;
import com.github.megatronking.netbare.NetBareUtils;
import com.github.megatronking.netbare.ip.Protocol;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A dumper analyzes /proc/net/ files to dump uid of the network session. This class may be a
 * battery-killer, but can set {@link NetBareConfig.Builder#dumpUid} to false to close the dumper.
 *
 * @author Megatron King
 * @since 2018-12-03 16:54
 */
public final class UidDumper {

    private static final int NET_ALIVE_SECONDS = 15;
    private static final int NET_CONCURRENCY_LEVEL = 6;
    private static final int NET_MAX_SIZE = 100;

    private static final Pattern IPV4_PATTERN = Pattern.compile("\\s+\\d+:\\s([0-9A-F]{8}):" +
            "([0-9A-F]{4})\\s([0-9A-F]{8}):([0-9A-F]{4})\\s([0-9A-F]{2})\\s[0-9A-F]{8}:[0-9A-F]{8}" +
            "\\s[0-9A-F]{2}:[0-9A-F]{8}\\s[0-9A-F]{8}\\s+([0-9A-F]+)", Pattern.CASE_INSENSITIVE
            | Pattern.UNIX_LINES);
    private static final Pattern IPV6_PATTERN = Pattern.compile("\\s+\\d+:\\s([0-9A-F]{32}):" +
            "([0-9A-F]{4})\\s([0-9A-F]{32}):([0-9A-F]{4})\\s([0-9A-F]{2})\\s[0-9A-F]{8}:[0-9A-F]{8}" +
            "\\s[0-9A-F]{2}:[0-9A-F]{8}\\s[0-9A-F]{8}\\s+([0-9A-F]+)", Pattern.CASE_INSENSITIVE
            | Pattern.UNIX_LINES);

    private final Cache<Integer, Net> mNetCaches;

    private final UidProvider mUidProvider;
    private final ArrayMap<Protocol, NetDumper[]> mDumpers;

    public UidDumper(String localIp, UidProvider provider) {
        this.mUidProvider = provider;
        this.mNetCaches = CacheBuilder.newBuilder()
                .expireAfterAccess(NET_ALIVE_SECONDS, TimeUnit.SECONDS)
                .concurrencyLevel(NET_CONCURRENCY_LEVEL)
                .maximumSize(NET_MAX_SIZE)
                .build();
        this.mDumpers = new ArrayMap<>(2);
        this.mDumpers.put(Protocol.TCP, new NetDumper[]{
                new NetDumper("/proc/net/tcp6", localIp, IPV6_PATTERN),
                new NetDumper("/proc/net/tcp", localIp, IPV4_PATTERN)});
        this.mDumpers.put(Protocol.UDP, new NetDumper[] {
                new NetDumper("/proc/net/udp6", localIp, IPV6_PATTERN),
                new NetDumper("/proc/net/udp", localIp, IPV4_PATTERN)});
    }

    public void request(final Session session) {
        if (mUidProvider != null) {
            int uid = mUidProvider.uid(session);
            if (uid != UidProvider.UID_UNKNOWN) {
                session.uid = uid;
                return;
            }
        }
        // Android Q abandons the access permission.
        if (NetBareUtils.isAndroidQ()) {
            return;
        }
        final int port = NetBareUtils.convertPort(session.localPort);
        try {
            Net net = mNetCaches.get(session.remoteIp, new Callable<Net>() {
                @Override
                public Net call() throws Exception {
                    NetDumper[] dumpers = mDumpers.get(session.protocol);
                    if (dumpers == null) {
                        throw new Exception();
                    }
                    for (NetDumper dumper : dumpers) {
                        Net net = dumper.dump(port);
                        if (net != null) {
                            return net;
                        }
                    }
                    // No find the uid.
                    throw new Exception();
                }
            });
            if (net != null) {
                session.uid = net.uid;
            }
        } catch (ExecutionException e) {
            // Not find the uid
        }
    }

    private static class NetDumper {

        private static final long MAX_DUMP_DURATION = 100;

        private String mArgs;
        private String mLocalIp;
        private Pattern mPattern;

        private NetDumper(String args, String localIp, Pattern pattern) {
            this.mArgs = args;
            this.mLocalIp = localIp;
            this.mPattern = pattern;
        }

        private Net dump(int port) {
            InputStream is = null;
            BufferedReader reader = null;
            try {
                is = new FileInputStream(mArgs);
                reader = new BufferedReader(new InputStreamReader(is));
                long now = System.currentTimeMillis();
                while (System.currentTimeMillis() - now < MAX_DUMP_DURATION) {
                    String line;
                    try {
                        line = reader.readLine();
                    } catch (IOException e) {
                        continue;
                    }
                    if (line == null || TextUtils.isEmpty(line.trim())) {
                        continue;
                    }
                    Matcher matcher = mPattern.matcher(line);
                    while (matcher.find()) {
                        int uid = NetBareUtils.parseInt(matcher.group(6), -1);
                        if (uid <= 0) {
                            continue;
                        }
                        int localPort = parsePort(matcher.group(2));
                        if (localPort != port) {
                            continue;
                        }
                        String localIp = parseIp(matcher.group(1));
                        if (localIp == null || !localIp.equals(mLocalIp)) {
                            continue;
                        }
                        String remoteIp = parseIp(matcher.group(3));
                        int remotePort = parsePort(matcher.group(4));
                        return new Net(uid, localIp, localPort, remoteIp, remotePort);
                    }
                }
            } catch (IOException e) {
                // Ignore
            } finally {
                NetBareUtils.closeQuietly(is);
                NetBareUtils.closeQuietly(reader);
            }
            return null;
        }

        private String parseIp(String ip) {
            ip = ip.substring(ip.length() - 8);
            int ip1 = NetBareUtils.parseInt(ip.substring(6, 8), 16, -1);
            int ip2 = NetBareUtils.parseInt(ip.substring(4, 6), 16, -1);
            int ip3 = NetBareUtils.parseInt(ip.substring(2, 4), 16, -1);
            int ip4 = NetBareUtils.parseInt(ip.substring(0, 2), 16, -1);
            if (ip1 < 0 || ip2 < 0 || ip3 < 0 || ip4 < 0) {
                return null;
            }
            return ip1 + "." + ip2 + "." + ip3 + "." + ip4;
        }

        private int parsePort(String port) {
            return NetBareUtils.parseInt(port, 16, -1);
        }

    }

}

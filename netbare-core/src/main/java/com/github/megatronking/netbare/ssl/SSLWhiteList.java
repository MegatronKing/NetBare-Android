package com.github.megatronking.netbare.ssl;

import java.util.HashSet;

/**
 * ip whitelist for ssl bypass
 * @author cuisoap
 * @since 2019/08/01 10:00
 */
public class SSLWhiteList {
    private static HashSet<String> whitelist = new HashSet<>();

    public static void add(String ip) {
        whitelist.add(ip);
    }

    public static boolean contains(String ip) {
        return whitelist.contains(ip);
    }
}

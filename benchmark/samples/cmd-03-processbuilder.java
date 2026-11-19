package com.owasp.webgoat.tools;

public class NetworkHealthCheck {
    public static Process pingTarget(String targetHost) throws Exception {
        return new ProcessBuilder("sh", "-c", "ping -c 1 " + targetHost).start();
    }
}


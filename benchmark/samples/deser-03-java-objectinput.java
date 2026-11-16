// Sample 15: Java ObjectInputStream Deserialization (Vulnerable)
// Source: OWASP WebGoat
// License: Apache-2.0

package org.owasp.webgoat.deserialization;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class UserSessionService {
    public Object deserializeToken(byte[] serializedData) throws Exception {
        // Vulnerability: arbitrary object deserialization without gadget filtering
        ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject();
    }
}


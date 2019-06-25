/*
 *  Copyright (c) 2011-2015 The original author or authors
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *       The Eclipse Public License is available at
 *       http://www.eclipse.org/legal/epl-v10.html
 *
 *       The Apache License v2.0 is available at
 *       http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package io.vertx.ext.mail.impl;

import io.vertx.core.MultiMap;
import io.vertx.core.http.CaseInsensitiveHeaders;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

/**
 * @author <a href="http://oss.lehmann.cx/">Alexander Lehmann</a>
 */
final class Utils {

  /**
   * utility class only
   */
  private Utils() {
  }

  /**
   * parse the capabilities string (single line) into a Set of auth String
   *
   * @param auths list of auth methods as String (e.g. "PLAIN LOGIN CRAM-MD5")
   * @return Set of supported auth methods
   */
  public static Set<String> parseCapaAuth(final String auths) {
    return new HashSet<>(splitByChar(auths, ' '));
  }

  /**
   * split string at each occurrence of a character (e.g. \n)
   *
   * @param message the string to split
   * @param ch      the char between which we split
   * @return the list lines
   */
  static List<String> splitByChar(final String message, final char ch) {
    List<String> lines = new ArrayList<>();
    int index = 0;
    int nextIndex;
    while ((nextIndex = message.indexOf(ch, index)) != -1) {
      lines.add(message.substring(index, nextIndex));
      index = nextIndex + 1;
    }
    lines.add(message.substring(index));
    return lines;
  }

  /**
   * get the hostname by resolving our own address
   *
   * this method is not async due to possible dns call, we run this with executeBlocking
   *
   * @return the hostname
   */
  public static String getHostname() {
    try {
      InetAddress ip = InetAddress.getLocalHost();
      return ip.getCanonicalHostName();
    } catch (UnknownHostException e) {
      // as a last resort, use localhost
      // another common convention would be to use the clients ip address
      // like [192.168.1.1] or [127.0.0.1]
      return "localhost";
    }
  }

  static void putIfNotNull(final JsonObject json, final String key, final Object value) {
    io.vertx.ext.mail.Utils.putIfNotNull(json, key, value);
  }

  static JsonObject multiMapToJson(final MultiMap headers) {
    return io.vertx.ext.mail.Utils.multiMapToJson(headers);
  }

  static MultiMap jsonToMultiMap(final JsonObject jsonHeaders) {
    return io.vertx.ext.mail.Utils.jsonToMultiMap(jsonHeaders);
  }

}

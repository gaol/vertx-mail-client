/*
 *  Copyright (c) 2011-2019 The original author or authors
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

package io.vertx.ext.mail;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.mail.impl.dkim.DKIMSigner;
import org.junit.Test;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.*;

/**
 * Tests for DKIMSignOptions.
 *
 * @author <a href="mailto: aoingl@gmail.com">Lin Gao</a>
 */
public class DKIMSignOptionsTest {

  // a PKCS#8 format private key for testing
  private final static String PRIVATE_KEY =
    "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKqSazYC8pj/JQmo\n" +
    "2ep0m3Shs6WGyHarknUzRJxiHWIVl2CvvOz2aCo4QCFk7nHjJbSQigA/xRrQ+Mzg\n" +
    "uNv4n/c+0MjMQscpyhrMYhza89jP3yMRjIEPJxiQzeMgGHTQifiBfB+2a8959YkB\n" +
    "oOJZuoY0TOEyB+Lm3j000B4evsRdAgMBAAECgYAdSw38dZ8iJVdABG6ANExqSEbo\n" +
    "22/b6XU6iXZ0AOmY6apYoXWpoFudPJHO6l2E04SrMNNyXYFFLLQ9wy4cIOOfs5yB\n" +
    "bdZ17tvOqSWT7nsCcuHpUvF89JNXnQvV2xwS6npp/tIuehMfxOxPLdN87Nge7BEy\n" +
    "6DCSW7U72pX9zjl1BQJBANv56R9X+XLWjW6n4s0tZ271XVYI4DlRxQHYHP3B7eLm\n" +
    "4DJtoHk65WU3kfHUeBNy/9TmpC25Gw6WTDco+mOS8wsCQQDGgVPCqhNDUcZYMeOH\n" +
    "X6hm+l8zBeTMF2udQbkl0dRdLFpbMtw3cg+WUjHg3AYv38P2ikSJZzgzdDyZzcxF\n" +
    "Hcc3AkBXoBNm8upg/mpUW/gSdzWuk3rcnKiE7LenZmkWBDw4mHNSYyz7XaSnTx2J\n" +
    "0XMLfFHAgyd/Ny85/lDZ4C7tn0nFAkEAkS2mz9lJa1PUZ05dZPWuGVqF47AszKNY\n" +
    "XlPiEGntEhPNJaQF8TsncT4+IoFouPzDun0XcRKfxOn/JFGiUu5bcwJAGbai+kPl\n" +
    "AoyfGLxOLu40IMNOHKhHOq8cm3dOC+HpQYpx96JGaQPY4kl3fos6e43DGp9vyOxv\n" +
    "VMj5fan+wzHLcw==";

  @Test
  public void testDefaultConstructor() {
    final DKIMSignOptions dkimOps = new DKIMSignOptions();
    assertNotNull(dkimOps);

    assertNull(dkimOps.getAuid());
    assertNull(dkimOps.getCopiedHeaders());
    assertNull(dkimOps.getSdid());
    assertNull(dkimOps.getSelector());
    assertFalse(dkimOps.isSignatureTimestamp());

    assertTrue(dkimOps.getSignedHeaders().stream().anyMatch(h -> h.equalsIgnoreCase("from")));
    assertEquals(DKIMSignAlgorithm.RSA_SHA256, dkimOps.getSignAlgo());
    assertEquals(MessageCanonic.SIMPLE, dkimOps.getHeaderCanonic());
    assertEquals(MessageCanonic.SIMPLE, dkimOps.getBodyCanonic());
    assertEquals(-1, dkimOps.getBodyLimit());
    assertEquals(-1, dkimOps.getExpireTime());

    JsonObject json = dkimOps.toJson();
    assertEquals(DKIMSignAlgorithm.RSA_SHA256, DKIMSignAlgorithm.valueOf(json.getString("signAlgo")));
    assertEquals(MessageCanonic.SIMPLE.name(), json.getString("headerCanonic"));
    assertEquals(MessageCanonic.SIMPLE.name(), json.getString("bodyCanonic"));

  }

  @Test
  public void testConfigFull() {
    final DKIMSignOptions dkimOps = new DKIMSignOptions();
    assertNotNull(dkimOps);

    dkimOps.setAuid("local-part@example.com");
    dkimOps.setSdid("example.com");
    dkimOps.setBodyCanonic(MessageCanonic.RELAXED);
    dkimOps.setBodyLimit(5000);
    dkimOps.setCopiedHeaders(Stream.of("From", "To").collect(Collectors.toList()));
    dkimOps.setSelector("exampleUser");
    dkimOps.setHeaderCanonic(MessageCanonic.SIMPLE);
    PubSecKeyOptions pubSecKeyOptions = new PubSecKeyOptions().setSecretKey(PRIVATE_KEY);
    dkimOps.setPubSecKeyOptions(pubSecKeyOptions);

    assertEquals("local-part@example.com", dkimOps.getAuid());
    assertEquals("example.com", dkimOps.getSdid());
    assertEquals(MessageCanonic.RELAXED, dkimOps.getBodyCanonic());
    assertEquals(5000, dkimOps.getBodyLimit());
    assertArrayEquals(new String[]{"From", "To"}, dkimOps.getCopiedHeaders().toArray());
    assertEquals("exampleUser", dkimOps.getSelector());
    assertEquals(MessageCanonic.SIMPLE, dkimOps.getHeaderCanonic());

    DKIMSigner dkimSigner = new DKIMSigner(dkimOps);
    assertNotNull(dkimSigner);

  }

  @Test
  public void testInvalidConfig() {
    final DKIMSignOptions dkimOps = new DKIMSignOptions();

    try {
      new DKIMSigner(dkimOps);
      fail("not here");
    } catch (IllegalStateException e) {
      assertEquals("PubSecKeyOptions must be specified to perform sign", e.getMessage());
    }

    dkimOps.setPubSecKeyOptions(new PubSecKeyOptions());
    try {
      new DKIMSigner(dkimOps);
      fail("not here");
    } catch (IllegalStateException e) {
      assertEquals("SecretKey must be specified to sign the email", e.getMessage());
    }

    dkimOps.getPubSecKeyOptions().setSecretKey(PRIVATE_KEY);
    dkimOps.setSdid("example.com");
    try {
      new DKIMSigner(dkimOps);
      fail("not here");
    } catch (IllegalStateException e) {
      assertEquals("The selector must be specified to be able to verify", e.getMessage());
    }
    dkimOps.setSelector("examUser");

    dkimOps.setSdid("example.com");
    dkimOps.setAuid("local-part@another.domain.com");
    try {
      new DKIMSigner(dkimOps);
      fail("not here");
    } catch (IllegalStateException e) {
      assertEquals("Identity domain mismatch, expected is: [xx]@[xx.]sdid", e.getMessage());
    }
  }

}

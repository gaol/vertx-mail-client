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

import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.mail.impl.dkim.DKIMSigner;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.Test;
import org.junit.runner.RunWith;

import javax.mail.internet.MimeMessage;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Test sending mails with DKIM enabled.
 *
 * @author <a href="mailto:aoingl@gmail.com">Lin Gao</a>
 */
@RunWith(VertxUnitRunner.class)
public class MailWithDKIMSignTest extends SMTPTestWiser {

  private static final String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKqSazYC8pj/JQmo\n" +
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

  // the corresponding public key for the private key above.
  private static final String pubKeyStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqkms2AvKY/yUJqNnqdJt0obOl\n" +
    "hsh2q5J1M0ScYh1iFZdgr7zs9mgqOEAhZO5x4yW0kIoAP8Ua0PjM4Ljb+J/3PtDI\n" +
    "zELHKcoazGIc2vPYz98jEYyBDycYkM3jIBh00In4gXwftmvPefWJAaDiWbqGNEzh\n" +
    "Mgfi5t49NNAeHr7EXQIDAQAB";

  private Signature verifier = null;
  {
    try {
      verifier = Signature.getInstance(DKIMSignAlgorithm.RSA_SHA256.getSignatureAlgorithm());
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(Base64.getMimeDecoder().decode(pubKeyStr));
      RSAPublicKey rsaKey = (RSAPublicKey) keyFactory.generatePublic(pubSpec);
      verifier.initVerify(rsaKey);
    } catch (Exception e) {
      throw new RuntimeException("Cannot init Signature for verification", e);
    }
  }

  private final HashingStrategy hashingStrategy = HashingStrategy.load();
  private final PubSecKeyOptions pubSecKeyOptions = new PubSecKeyOptions().setSymmetric(false)
    .setSecretKey(privateKey).setPublicKey(pubKeyStr);
  private final DKIMSignOptions dkimOptionsBase = new DKIMSignOptions().setPubSecKeyOptions(pubSecKeyOptions)
    .setAuid("from@example.com").setSdid("example.com").setSelector("lgao").setSignAlgo(DKIMSignAlgorithm.RSA_SHA256);

  private MailClient dkimMailClient(DKIMSignOptions dkimOps) {
    return MailClient.createNonShared(vertx, configLogin().setEnableDKIM(true).addDKIMOption(dkimOps));
  }

  @Test
  public void testMailRelaxedRelaxedPlain(TestContext testContext) {
    this.testContext = testContext;
    String text = "Message Body";
    MailMessage message = exampleMessage().setText(text).setSubject("relaxed/relaxed plain text email");
    DKIMSignOptions dkimOps = new DKIMSignOptions(dkimOptionsBase)
      .setHeaderCanonic(MessageCanonic.RELAXED).setBodyCanonic(MessageCanonic.RELAXED);
    testSuccess(dkimMailClient(dkimOps), message, () -> {
      testDKIMSign(dkimOps, message, testContext);
    });
  }

  private void testDKIMSign(DKIMSignOptions dkimOps, MailMessage message, TestContext ctx) throws Exception {
    MimeMessage mimeMessage = wiser.getMessages().get(0).getMimeMessage();
    String dkimSignTagsList = mimeMessage.getHeader(DKIMSigner.DKIM_SIGNATURE_HEADER)[0];
    ctx.assertNotNull(dkimSignTagsList);
    Map<String, String> signTags = new HashMap<>();
    Arrays.stream(dkimSignTagsList.split(";")).map(String::trim).forEach(part -> {
      int idx = part.indexOf("=");
      signTags.put(part.substring(0, idx), part.substring(idx + 1));
    });
    ctx.assertEquals("1", signTags.get("v"));
    ctx.assertEquals(DKIMSignAlgorithm.RSA_SHA256.getAlgorightmName(), signTags.get("a"));
    ctx.assertEquals(dkimOps.getHeaderCanonic().getCanonic() + "/" + dkimOps.getBodyCanonic().getCanonic(), signTags.get("c"));
    ctx.assertEquals("example.com", signTags.get("d"));
    ctx.assertEquals("from@example.com", signTags.get("i"));
    ctx.assertEquals("lgao", signTags.get("s"));
    ctx.assertEquals("from:reply-to:subject:date:to:cc", signTags.get("h"));
    testBodyHash(dkimOps, signTags.get("bh"), mimeMessage, testContext);
    testWholeSignature(dkimOps, signTags.get("bh"), signTags.get("b"), mimeMessage, testContext);
  }

  private void testWholeSignature(DKIMSignOptions dkimOps, String bh, String b, MimeMessage msg, TestContext ctx) throws Exception {
    //TODO
  }

  private void testBodyHash(DKIMSignOptions dkimOps, String bodyHash, MimeMessage msg, TestContext ctx) throws Exception {
    String hash = calculateHash(msg.getRawInputStream());
    System.out.println("hash in header: " + bodyHash);
    System.out.println("hash by calculate: " + hash);
    ctx.assertEquals(hash, bodyHash);
  }

  private String calculateHash(InputStream inputStream) throws Exception {
    MessageDigest md = MessageDigest.getInstance("sha-256");
    int nRead;
    byte[] buffer = new byte[512];
    while ((nRead = inputStream.read(buffer, 0, buffer.length)) != -1) {
      md.update(buffer, 0, nRead);
    }
    return Base64.getEncoder().encodeToString(md.digest());
  }

}

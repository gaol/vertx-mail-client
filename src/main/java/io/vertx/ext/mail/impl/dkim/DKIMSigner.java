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

package io.vertx.ext.mail.impl.dkim;

import io.vertx.core.*;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.ext.auth.HashingAlgorithm;
import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.mail.DKIMSignAlgorithm;
import io.vertx.ext.mail.DKIMSignOptions;
import io.vertx.ext.mail.MessageCanonic;
import io.vertx.ext.mail.mailencoder.EncodedPart;
import io.vertx.ext.mail.mailencoder.Utils;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * DKIM Signature Singer to sign the email according to the configurations.
 *
 * Refer to: https://tools.ietf.org/html/rfc6376
 *
 * @author <a href="mailto: aoingl@gmail.com">Lin Gao</a>
 */
public class DKIMSigner {

  public static final String DKIM_SIGNATURE_HEADER = "DKIM-Signature";

  private static final Logger logger = LoggerFactory.getLogger(DKIMSigner.class);

  private final DKIMSignOptions dkimSignOptions;
  private final HashingStrategy hashingStrategy = HashingStrategy.load();
  private final Signature signatureService;
  private static final Pattern DELIMITER = Pattern.compile("[\r\n]");

  /**
   * The Constuctor of DKIMSigner.
   *
   * It validates the {@link DKIMSignOptions} which may throws IllegalStateException.
   *
   * It tries to initialize a {@link Signature} so that it can be reused on each sign.
   *
   * @param dkimSignOptions the {@link DKIMSignOptions} used to perform the DKIM Sign.
   * @throws IllegalStateException the exception to throw on invalid configurations.
   */
  public DKIMSigner(DKIMSignOptions dkimSignOptions) {
    this.dkimSignOptions = dkimSignOptions;
    validate(this.dkimSignOptions);
    try {
      KeyFactory kf = KeyFactory.getInstance("RSA");
      final PKCS8EncodedKeySpec keyspec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(dkimSignOptions.getPubSecKeyOptions().getSecretKey()));
      final PrivateKey privateKey = kf.generatePrivate(keyspec);
      signatureService = Signature.getInstance(dkimSignOptions.getSignAlgo().getSignatureAlgorithm());
      signatureService.initSign(privateKey);
    } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
      throw new IllegalStateException("Failed to init the Signature", e);
    }
  }

  /**
   * Validate whether the values are following the spec.
   *
   * @throws IllegalStateException on any specification violence.
   */
  private void validate(DKIMSignOptions ops) throws IllegalStateException {
    // required fields check
    checkRequiredFields(ops);
    // check identity and sdid
    final String auid = ops.getAuid();
    if (auid != null) {
      String sdid = ops.getSdid();
      if (!auid.toLowerCase().endsWith("@" + sdid.toLowerCase())
        && !auid.toLowerCase().endsWith("." + sdid.toLowerCase())) {
        throw new IllegalStateException("Identity domain mismatch, expected is: [xx]@[xx.]sdid");
      }
    }

    // check required signed header field: 'from'
    if (ops.getSignedHeaders().stream().noneMatch(h -> h.equalsIgnoreCase("from"))) {
      throw new IllegalStateException("From field must be selected to sign.");
    }

    // check excluded headers
    Arrays.asList("return-path", "received", "comments", "keywords", DKIM_SIGNATURE_HEADER).forEach(h -> {
      if (ops.getSignedHeaders().stream().anyMatch(hh -> hh.equalsIgnoreCase(h))) {
        throw new IllegalStateException("Header: " + h + " should not be signed.");
      }
    });
  }

  private void checkRequiredFields(DKIMSignOptions ops) {
    if (ops.getSignAlgo() == null) {
      throw new IllegalStateException("Sign Algorithm is required: rsa-sha1 or rsa-sha256");
    }
    if (ops.getPubSecKeyOptions() == null) {
      throw new IllegalStateException("PubSecKeyOptions must be specified to perform sign");
    }
    if (ops.getPubSecKeyOptions().getSecretKey() == null) {
      throw new IllegalStateException("SecretKey must be specified to sign the email");
    }
    if (ops.getSignedHeaders() == null || ops.getSignedHeaders().isEmpty()) {
      throw new IllegalStateException("Email header fields to sign must be set");
    }
    if (ops.getSdid() == null) {
      throw new IllegalStateException("Singing Domain Identifier(SDID) must be specified");
    }
    if (ops.getSelector() == null) {
      throw new IllegalStateException("The selector must be specified to be able to verify");
    }
  }

  /**
   * Perform the DKIM Signature sign action.
   *
   * @param context the Vert.x Context so that it can run the blocking code like calculating the body hash
   * @param encodedMessage The Encoded Message to be ready to sent to the wire
   * @return The Future with a result as the value of header: 'DKIM-Signature'
   */
  public Future<String> signEmail(Context context, EncodedPart encodedMessage) {
    Promise<String> promise = Promise.promise();
    context.executeBlocking(bodyHashing(context, encodedMessage), bhr -> {
      if (bhr.succeeded()) {
        String bh = bhr.result();
        System.err.println("DKIM Body Hash: " + bh);
        final StringBuilder dkimTagListBuilder = dkimTagList(encodedMessage).append("bh=").append(bh).append("; b=");
        String dkimSignHeaderCanonic = canonicHeader(DKIM_SIGNATURE_HEADER, dkimTagListBuilder.toString());
        final StringBuilder tobeSigned = headersToSign(encodedMessage).append(dkimSignHeaderCanonic);
        try {
          System.err.println("To be signed: ##\n" + tobeSigned + "\n:-##");
          String returnStr;
          synchronized (signatureService) {
            signatureService.update(tobeSigned.toString().getBytes());
            String sig = Base64.getEncoder().encodeToString(signatureService.sign());
            returnStr = dkimTagListBuilder.append(sig).toString();
          }
          promise.complete(returnStr);
        } catch (SignatureException e) {
          logger.warn("Failed to sign the email", e);
          promise.fail(e);
        }
      } else {
        logger.warn("Failed to calculate the body hash", bhr.cause());
        promise.fail(bhr.cause());
      }
    });
    return promise.future();
  }

  private String dkimMailBody(EncodedPart encodedMessage, DKIMSignOptions dkimSignOptions) {
    Scanner scanner = new Scanner(encodedMessage.body()).useDelimiter(DELIMITER);
    StringBuilder sb = new StringBuilder();
    while (scanner.hasNext()) {
      sb.append(canonicBodyLine(scanner.nextLine(), dkimSignOptions.getBodyCanonic()));
    }
    String lines = sb.toString().replaceFirst("[\r\n]*$", "\r\n");
    if (dkimSignOptions.getBodyLimit() > 0 && dkimSignOptions.getBodyLimit() < lines.length()) {
      lines = lines.substring(0, dkimSignOptions.getBodyLimit());
    }
    return lines;
  }

  private String canonicBodyLine(String line, MessageCanonic canonic) {
    if (MessageCanonic.RELAXED == canonic) {
      line = line.replaceAll("\r\n[\t ]+", " ");
      line = line.replaceAll("[\t ]+", " ");
      line = line.trim();
    }
    return line + "\r\n";
  }

  // https://tools.ietf.org/html/rfc6376#section-3.7
  private Handler<Promise<String>> bodyHashing(Context context, EncodedPart encodedMessage) {
    return p -> {
      // running in blocking mode
      try {
        HashingAlgorithm hashingAlgorithm = hashingStrategy.get(dkimSignOptions.getSignAlgo().getHashAlgoId());
        if (encodedMessage.parts() != null && encodedMessage.parts().size() > 0) {
          // it is a multipart message, calculate all into buffer for now, even for the ReadStream of the attachment.
          MessageDigest md = MessageDigest.getInstance(dkimSignOptions.getSignAlgo().getHashAlgorithm());

          for (EncodedPart part: encodedMessage.parts()) {
            // boundary start
            md.update(("--" + encodedMessage.boundary()).getBytes());
            // part headers
            md.update(encodedMessage.headers().toString().getBytes());
            md.update("\r\n".getBytes());
            md.update(dkimMailBody(part, this.dkimSignOptions).getBytes());
          }
          // boundary end
          md.update(("--" + encodedMessage.boundary() + "--").getBytes());
          String bh = Base64.getEncoder().encodeToString(md.digest());
          System.err.println("Body Hash of Multipart: " + bh);
          p.complete(bh);
        } else {
          // it is a normal message
          String canonicBody = dkimMailBody(encodedMessage, this.dkimSignOptions);
//          System.out.println("Body To Hash: ===\n" + canonicBody + "\n===");
          String bh = hashingAlgorithm.hash(null, canonicBody);
          p.complete(bh);
        }
      } catch (Exception e) {
        p.fail(e);
      }
    };
  }

  private StringBuilder headersToSign(EncodedPart encodedMessage) {
    final StringBuilder signHeaders = new StringBuilder();
    // keep the order in the list, see: https://tools.ietf.org/html/rfc6376#section-3.7
    for (String header: dkimSignOptions.getSignedHeaders()) {
      encodedMessage.headers().entries().forEach(e -> {
        if (e.getKey().equalsIgnoreCase(header)) {
          signHeaders.append(canonicHeader(header, e.getValue())).append("\r\n");
        }
      });
    }
    return signHeaders;
  }

  /**
   * Computes DKIM Signature Sign tag list.
   *
   * @param encodedMessage the encoded message which is ready to write to the wire
   * @return the StringBuilder represents the tag list based on the specified {@link DKIMSignOptions}
   */
  private StringBuilder dkimTagList(EncodedPart encodedMessage) {
    final StringBuilder dkimSignHeader = new StringBuilder();
    // version is always the first one
    dkimSignHeader.append("v=1; ");
    // sign algorithm
    dkimSignHeader.append("a=").append(this.dkimSignOptions.getSignAlgo().getDKIMAlgoName()).append("; ");
    // optional message canonic
    MessageCanonic bodyCanonic = this.dkimSignOptions.getBodyCanonic();
    MessageCanonic headerCanonic = this.dkimSignOptions.getHeaderCanonic();
    dkimSignHeader.append("c=").append(headerCanonic.getCanonic()).append("/").append(bodyCanonic.getCanonic()).append("; ");

    // sdid
    dkimSignHeader.append("d=").append(dkimQuotedPrintable(this.dkimSignOptions.getSdid())).append("; ");
    // optional auid
    String auid = this.dkimSignOptions.getAuid();
    if (auid != null) {
      dkimSignHeader.append("i=").append(dkimQuotedPrintable(auid)).append("; ");
    }
    // selector
    dkimSignHeader.append("s=").append(dkimQuotedPrintable(this.dkimSignOptions.getSelector())).append("; ");
    // h=
    String signHeadersString = String.join(":", this.dkimSignOptions.getSignedHeaders());
    dkimSignHeader.append("h=").append(signHeadersString).append("; ");
    // optional sign time
    if (this.dkimSignOptions.isSignatureTimestamp() || this.dkimSignOptions.getExpireTime() > 0) {
      long time = new Date().getTime() / 1000; // in seconds
      dkimSignHeader.append("t=").append(time).append("; ");
      if (this.dkimSignOptions.getExpireTime() > 0) {
        long expire = time + this.dkimSignOptions.getExpireTime();
        dkimSignHeader.append("x=").append(expire).append("; ");
      }
    }
    // optional copied headers
    if (dkimSignOptions.getCopiedHeaders() != null && dkimSignOptions.getCopiedHeaders().size() > 0) {
      dkimSignHeader.append("z=").append(copiedHeaders(dkimSignOptions.getCopiedHeaders(), encodedMessage)).append("; ");
    }
    return dkimSignHeader;
  }

  private String copiedHeaders(List<String> headers, EncodedPart encodedMessage) {
    return headers.stream().map(h -> {
      String hValue = encodedMessage.headers().get(h);
      if (hValue != null) {
        return h + ":" + dkimQuotedPrintableCopiedHeader(hValue);
      }
      throw new RuntimeException("Unknown email header: " + h + " in copied headers.");
    }).collect(Collectors.joining("|"));
  }

  // https://tools.ietf.org/html/rfc6376#section-2.11
  private static String dkimQuotedPrintable(String str) {
    String dkimStr = Utils.encodeQP(str);
    dkimStr = dkimStr.replaceAll(";", "=3B");
    dkimStr = dkimStr.replaceAll(" ", "=20");
    return dkimStr;
  }

  // https://tools.ietf.org/html/rfc6376#page-25
  private String dkimQuotedPrintableCopiedHeader(String value) {
    return dkimQuotedPrintable(value).replaceAll("\\|", "=7C");
  }

  /**
   * Do Email Header Canonicalization.
   *
   * https://tools.ietf.org/html/rfc6376#section-3.4.1
   * https://tools.ietf.org/html/rfc6376#section-3.4.2
   *
   * @param emailHeaderName the email header name used for the canonicalization.
   * @param emailHeaderValue the email header value for the canonicalization.
   * @return the canonicalization email header in format of 'Name':'Value'.
   */
  private String canonicHeader(String emailHeaderName, String emailHeaderValue) {
    if (this.dkimSignOptions.getHeaderCanonic() == MessageCanonic.SIMPLE) {
      return emailHeaderName + ": " + emailHeaderValue;
    }
    String headerName = emailHeaderName.trim().toLowerCase();
    emailHeaderValue = emailHeaderValue.replaceAll("\r\n[\t ]", " ");
    emailHeaderValue = emailHeaderValue.replaceAll("[\t ]+", " ");
    emailHeaderValue = emailHeaderValue.trim();
    return headerName + ":" + emailHeaderValue;
  }

}

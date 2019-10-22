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

import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.*;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.streams.ReadStream;
import io.vertx.core.streams.WriteStream;
import io.vertx.ext.auth.HashingAlgorithm;
import io.vertx.ext.auth.HashingStrategy;
import io.vertx.ext.mail.DKIMSignOptions;
import io.vertx.ext.mail.MessageCanonic;
import io.vertx.ext.mail.mailencoder.EncodedPart;
import io.vertx.ext.mail.mailencoder.Utils;

import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
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
        System.err.println("DKIM Body HASH: " + bh);
        final StringBuilder dkimTagListBuilder = dkimTagList(encodedMessage).append("bh=").append(bh).append("; b=");
        String dkimSignHeaderCanonic = canonicHeader(DKIM_SIGNATURE_HEADER, dkimTagListBuilder.toString());
        final StringBuilder tobeSigned = headersToSign(encodedMessage).append(dkimSignHeaderCanonic);
        try {
          signatureService.update(tobeSigned.toString().getBytes());
          dkimTagListBuilder.append(Base64.getEncoder().encodeToString(signatureService.sign()).replaceAll("[\r\n]+", "\r\n\t"));
          promise.complete(dkimTagListBuilder.toString());
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

//  public static String CRLF(String body) {
//    ByteArrayOutputStream baos = new ByteArrayOutputStream();
//    try (CRLFOutputStream crlfos = new CRLFOutputStream(baos)) {
//      crlfos.write(body.getBytes());
//    } catch (IOException e) {
//      throw new IllegalStateException("The body conversion to MIME canonical CRLF line terminator failed", e);
//    }
//    return baos.toString();
//  }

  // TODO: maybe a ReadStream for large email body
  // https://tools.ietf.org/html/rfc6376#section-3.7
  private Handler<Promise<String>> bodyHashing(Context context, EncodedPart encodedMessage) {
    return p -> {
      // running in blocking mode
      try {
        ReadStream<Buffer> dkimStream = encodedMessage.dkimBodyStream(context, this.dkimSignOptions);
        final Buffer buffer = Buffer.buffer();
        dkimStream.pipe().to(new WriteStream<Buffer>() {
          private AtomicBoolean ended = new AtomicBoolean(false);
          private Handler<Throwable> exceptionHandler;
          private Handler<AsyncResult<Void>> endHandler;

          @Override
          public WriteStream<Buffer> exceptionHandler(Handler<Throwable> handler) {
            this.exceptionHandler = handler;
            return this;
          }

          @Override
          public Future<Void> write(Buffer data) {
            Promise<Void> promise = Promise.promise();
            write(data, promise);
            return promise.future();
          }

          @Override
          public void write(Buffer data, Handler<AsyncResult<Void>> handler) {
            System.out.println("Writing: " + data);
            try {
              buffer.appendBuffer(data);
              if (ended.compareAndSet(false, true) && this.endHandler != null) {
                this.endHandler.handle(null);
              }
            } catch (Exception e) {
              if (handler != null) {
                handler.handle(Future.failedFuture(e));
              }
              if (this.exceptionHandler != null) {
                this.exceptionHandler.handle(e);
              }
            } finally {
              if (handler != null) {
                handler.handle(Future.succeededFuture());
              }
            }
          }

          @Override
          public void end(Handler<AsyncResult<Void>> handler) {
            this.endHandler = handler;
            if (ended.get() && this.endHandler != null) {
              this.endHandler.handle(Future.succeededFuture());
            }
          }

          @Override
          public WriteStream setWriteQueueMaxSize(int maxSize) {
            return this;
          }

          @Override
          public boolean writeQueueFull() {
            return false;
          }

          @Override
          public WriteStream drainHandler(@Nullable Handler<Void> handler) {
            return this;
          }
        }, h -> {
          if (h.succeeded()) {
            HashingAlgorithm hashingAlgorithm = hashingStrategy.get(dkimSignOptions.getSignAlgo().getHashAlgorithm());
//          String canonicBody = canonicBody(CRLF(encodedMessage.body()));
//          if (dkimSignOptions.getBodyLimit() > 0) {
//            canonicBody = canonicBody.substring(0, Math.min(dkimSignOptions.getBodyLimit(), canonicBody.length() - 1));
//          }
            System.out.println("Body To Hash: ===\n" + buffer.toString() + "\n===");
            String bh = hashingAlgorithm.hash(null, buffer.toString());
            p.complete(bh);
          } else {
            p.fail(h.cause());
          }
        });
      } catch (Exception e) {
        p.fail(e);
      }
    };
  }

  private StringBuilder headersToSign(EncodedPart encodedMessage) {
    final StringBuilder signeHeaders = new StringBuilder();
    // keep the order in the list, see: https://tools.ietf.org/html/rfc6376#section-3.7
    for (String header: dkimSignOptions.getSignedHeaders()) {
      String headerValue = encodedMessage.headers().get(header);
      if (headerValue == null) {
        continue;
      }
      String cannonicHeader = canonicHeader(header, headerValue);
      signeHeaders.append(cannonicHeader).append("\r\n");
    }
    return signeHeaders;
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
    dkimSignHeader.append("a=").append(this.dkimSignOptions.getSignAlgo().getAlgorightmName()).append("; ");
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
    dkimSignHeader.append("h=").append(String.join(":", this.dkimSignOptions.getSignedHeaders())).append("; ");
    // optional sign time
    if (this.dkimSignOptions.isSignatureTimestmap() || this.dkimSignOptions.getExpireTime() > 0) {
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

//  private static class CRLFOutputStream extends FilterOutputStream {
//    private int lastb = -1;
//    private static byte[] newline;
//    static {
//      newline = new byte[2];
//      newline[0] = (byte)'\r';
//      newline[1] = (byte)'\n';
//    }
//
//    CRLFOutputStream(OutputStream os) {
//      super(os);
//    }
//
//    public void write(int b) throws IOException {
//      if (b == '\r') {
//        out.write(newline);
//      } else if (b == '\n') {
//        if (lastb != '\r')
//          out.write(newline);
//      } else {
//        out.write(b);
//      }
//      lastb = b;
//    }
//
//    public void write(byte[] b) throws IOException {
//      write(b, 0, b.length);
//    }
//
//    public void write(byte[] b, int off, int len) throws IOException {
//      int start = off;
//
//      len += off;
//      for (int i = start; i < len ; i++) {
//        if (b[i] == '\r') {
//          out.write(b, start, i - start);
//          out.write(newline);
//          start = i + 1;
//        } else if (b[i] == '\n') {
//          if (lastb != '\r') {
//            out.write(b, start, i - start);
//            out.write(newline);
//          }
//          start = i + 1;
//        }
//        lastb = b[i];
//      }
//      if ((len - start) > 0)
//        out.write(b, start, len - start);
//    }
//  }


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
    String headerName = emailHeaderName;
    if (this.dkimSignOptions.getHeaderCanonic() == MessageCanonic.RELAXED) {
      headerName = emailHeaderName.trim().toLowerCase();
    }
    return headerName + ":" + canonicHeaderValue(emailHeaderValue);
  }

  private String canonicHeaderValue(String emailHeaderValue) {
    if (this.dkimSignOptions.getHeaderCanonic() == MessageCanonic.SIMPLE) {
      return emailHeaderValue;
    }
    return processLine(emailHeaderValue, this.dkimSignOptions.getHeaderCanonic());
  }

  public static String processLine(String line, MessageCanonic canonic) {
    if (MessageCanonic.RELAXED == canonic) {
      line = line.replaceAll("[\r\n\t ]+", " ");
      line = line.replaceAll("(?m)[\t\r\n ]+$", "");
    }
    return line + "\r\n";
  }

  /**
   * Do Email Body Canonicalization.
   *
   * https://tools.ietf.org/html/rfc6376#section-3.4.3
   * https://tools.ietf.org/html/rfc6376#section-3.4.4
   *
   * @param emailBody the email body used to
   */
  private String canonicBody(String emailBody) {
    if (emailBody == null || "".equals(emailBody) ) {
      return "\r\n";
    }
    if (MessageCanonic.RELAXED == this.dkimSignOptions.getBodyCanonic()) {
      // relaxed:
      return stripTrailingLines(compressWSP(stripTrailingWSP(emailBody)));
    } else {
      // simple: just strip the trailing lines
      return stripTrailingLines(emailBody);
    }
  }

  // used for head canonic only
  private String unFolded(String string) {
    return string.replaceAll("\r\n", "");
  }

  private String compressWSP(String string) {
    return string.replaceAll("[\t ]+", " ");
  }

  // used for body hashing only
  private String stripTrailingWSP(String string) {
    return string.replaceAll("[\t ]+\r\n", "\r\n");
  }

  // used for body hashing only
  private String stripTrailingLines(String string) {
    if (string.length() < 2 || !"\r\n".equals(string.substring(string.length() - 2))) {
      return string + "\r\n";
    }
    String str = string;
    while (str.length() >= 4 && "\r\n\r\n".equals(str.substring(str.length() - 4))) {
      str = str.substring(0, str.length() - 2);
    }
    return !str.endsWith("\r\n") ? str + "\r\n" : str;
  }

}

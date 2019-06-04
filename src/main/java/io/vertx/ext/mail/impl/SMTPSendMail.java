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

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.impl.NoStackTraceThrowable;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.core.streams.ReadStream;
import io.vertx.ext.mail.MailConfig;
import io.vertx.ext.mail.MailMessage;
import io.vertx.ext.mail.MailResult;
import io.vertx.ext.mail.mailencoder.EmailAddress;
import io.vertx.ext.mail.mailencoder.EncodedPart;
import io.vertx.ext.mail.mailencoder.MailEncoder;
import io.vertx.ext.mail.mailencoder.Utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

class SMTPSendMail {

  private static final Logger log = LoggerFactory.getLogger(SMTPSendMail.class);

  private final SMTPConnection connection;
  private final MailMessage email;
  private final MailConfig config;
  private final Handler<AsyncResult<MailResult>> resultHandler;
  private final MailResult mailResult;
  private final EncodedPart encodedPart;
  private final AtomicLong wrottern = new AtomicLong();

  SMTPSendMail(SMTPConnection connection, MailMessage email, MailConfig config, String hostname, Handler<AsyncResult<MailResult>> resultHandler) {
    this.connection = connection;
    this.email = email;
    this.config = config;
    this.resultHandler = resultHandler;
    this.mailResult = new MailResult();
    final MailEncoder encoder = new MailEncoder(email, hostname);
    this.encodedPart = encoder.encodeMail();
    this.mailResult.setMessageID(encoder.getMessageID());
  }

  void start() {
    try {
      if (checkSize()) {
        mailFromCmd();
      }
    } catch (Exception e) {
      handleError(e);
    }
  }

  /**
   * Check if message size is allowed if size is supported.
   * <p>
   * returns true if the message is allowed, have to make sure that when returning from the handleError method it
   * doesn't continue with the mail from operation
   */
  private boolean checkSize() {
    final int size = connection.getCapa().getSize();
    if (size > 0 && encodedPart.size() > size) {
      handleError("message exceeds allowed size limit");
      return false;
    } else {
      return true;
    }
  }

  private void mailFromCmd() {
    try {
      String fromAddr;
      String bounceAddr = email.getBounceAddress();
      if (bounceAddr != null && !bounceAddr.isEmpty()) {
        fromAddr = bounceAddr;
      } else {
        fromAddr = email.getFrom();
      }
      EmailAddress from = new EmailAddress(fromAddr);
      String sizeParameter;
      if (connection.getCapa().getSize() > 0) {
        sizeParameter = " SIZE=" + encodedPart.size();
      } else {
        sizeParameter = "";
      }
      final String line = "MAIL FROM:<" + from.getEmail() + ">" + sizeParameter;
      connection.write(line, message -> {
        if (log.isDebugEnabled()) {
          wrottern.getAndAdd(line.length());
          log.debug("MAIL FROM result: " + message);
        }
        if (StatusCode.isStatusOk(message)) {
          rcptToCmd();
        } else {
          log.warn("sender address not accepted: " + message);
          handleError("sender address not accepted: " + message);
        }
      });
    } catch (IllegalArgumentException e) {
      log.error("address exception", e);
      handleError(e);
    }
  }

  private void rcptToCmd() {
    List<String> recipientAddrs = new ArrayList<>();
    if (email.getTo() != null) {
      recipientAddrs.addAll(email.getTo());
    }
    if (email.getCc() != null) {
      recipientAddrs.addAll(email.getCc());
    }
    if (email.getBcc() != null) {
      recipientAddrs.addAll(email.getBcc());
    }
    rcptToCmd(recipientAddrs, 0);
  }

  private void rcptToCmd(List<String> recipientAddrs, int i) {
    try {
      EmailAddress toAddr = new EmailAddress(recipientAddrs.get(i));
      final String line = "RCPT TO:<" + toAddr.getEmail() + ">";
      connection.write(line, message -> {
        if (log.isDebugEnabled()) {
          wrottern.getAndAdd(line.length());
        }
        if (StatusCode.isStatusOk(message)) {
          log.debug("RCPT TO result: " + message);
          mailResult.getRecipients().add(toAddr.getEmail());
          nextRcpt(recipientAddrs, i);
        } else {
          if (config.isAllowRcptErrors()) {
            log.warn("recipient address not accepted, continuing: " + message);
            nextRcpt(recipientAddrs, i);
          } else {
            log.warn("recipient address not accepted: " + message);
            handleError("recipient address not accepted: " + message);
          }
        }
      });
    } catch (IllegalArgumentException e) {
      log.error("address exception", e);
      handleError(e);
    }
  }

  private void nextRcpt(List<String> recipientAddrs, int i) {
    if (i + 1 < recipientAddrs.size()) {
      rcptToCmd(recipientAddrs, i + 1);
    } else {
      if (mailResult.getRecipients().size() > 0) {
        dataCmd();
      } else {
        log.warn("no recipient addresses were accepted, not sending mail");
        handleError("no recipient addresses were accepted, not sending mail");
      }
    }
  }

  private void handleError(Throwable throwable) {
    resultHandler.handle(Future.failedFuture(throwable));
  }

  private void handleError(String message) {
    handleError(new NoStackTraceThrowable(message));
  }

  private void dataCmd() {
    connection.write("DATA", message -> {
      if (log.isDebugEnabled()) {
        wrottern.getAndAdd(4);
        log.debug("DATA result: " + message);
      }
      if (StatusCode.isStatusOk(message)) {
        sendMaildata();
      } else {
        log.warn("DATA command not accepted: " + message);
        handleError("DATA command not accepted: " + message);
      }
    });
  }

  private void sendMaildata() {
    sendDataOfPart(encodedPart, handlerInContext(v -> connection.write(".", message -> {
      if (StatusCode.isStatusOk(message)) {
        resultHandler.handle(Future.succeededFuture(mailResult));
      } else {
        log.warn("sending data failed: " + message);
        handleError("sending data failed: " + message);
      }
    })));
  }

  private void sendDataOfPart(EncodedPart part, Handler<Void> endHandler) {
    if (isMultiPart(part)) {
      sendMailHeaders(part);
      sendMultiPart(part, 0, endHandler);
    } else {
      sendRegularPart(part, endHandler);
    }
  }

  private void sendMultiPart(EncodedPart part, int i, Handler<Void> endHandler) {
    // write boundary start
    final StringBuilder sb = new StringBuilder("--").append(part.boundary());
    connection.writeLine(sb.toString(), wrottern.getAndAdd(sb.length()) < 1000);
    EncodedPart thePart = part.parts().get(i);

    Handler<Void> nextHandler;
    if (i == part.parts().size() - 1) {
      // this is the last part
      nextHandler = v -> {
        connection.writeLine(sb.append("--").toString(), wrottern.getAndAdd(sb.length()) < 1000);
        endHandler.handle(null);
      };
    } else {
      // next part to do
      nextHandler = v -> sendMultiPart(part, i + 1, endHandler);
    }
    if (isMultiPart(thePart)) {
      nextHandler.handle(null);
    } else {
      // send single part with the endHandler
      sendRegularPart(thePart, nextHandler);
    }
  }

  private boolean isMultiPart(EncodedPart part) {
    return part.parts() != null && part.parts().size() > 0;
  }

  private void sendMailHeaders(EncodedPart part) {
    for (Map.Entry<String, String> entry: part.headers()) {
      connection.writeLine(entry.toString(), wrottern.getAndAdd(entry.toString().length()) < 1000);
    }
    // send empty line between headers and body
    connection.writeLine("", wrottern.get() < 1000);
  }

  private void sendRegularPart(EncodedPart part, Handler<Void> endHandler) {
    sendMailHeaders(part);
    if (part.body() != null) {
      // send body string
      for (String bodyLine: part.body().split("\n")) {
        String line = bodyLine.startsWith(".") ? "." + bodyLine : bodyLine;
        connection.writeLine(line, wrottern.getAndAdd(line.length()) < 1000);
      }
      endHandler.handle(null);
    } else if (part.bodyStream() != null) {
      writeStream(part.bodyStream(), endHandler);
    } else {
      throw new IllegalStateException("No mail body and stream found");
    }
  }

  private void writeStream(ReadStream<Buffer> stream, Handler<Void> endHandler) {
    final int size = 57;
    final int fetchSize = size * 64;
    final AtomicReference<Buffer> streamBuffer = new AtomicReference<>(Buffer.buffer());
    stream.handler(b -> connection.getContext().runOnContext(v -> {
      Buffer buffer = streamBuffer.get().appendBuffer(b);
      int start = 0;
      while(start + size < buffer.length()) {
        String theLine = Utils.base64(buffer.getBytes(start, start + size));
        connection.writeLine(theLine, wrottern.getAndAdd(theLine.length()) < 1000);
        start += size;
      }
      streamBuffer.set(buffer.getBuffer(start, buffer.length()));
      stream.fetch(fetchSize);
    })).fetch(fetchSize).endHandler(handlerInContext(v -> {
      if (streamBuffer.get().length() > 0) {
        String theLine = Utils.base64(streamBuffer.get().getBytes());
        connection.writeLine(theLine, wrottern.getAndAdd(theLine.length()) < 1000);
      }
      endHandler.handle(null);
    }));
  }

  private Handler<Void> handlerInContext(Handler<Void> handler) {
    return vv -> connection.getContext().runOnContext(v -> handler.handle(null));
  }
}

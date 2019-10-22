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

package io.vertx.ext.mail.mailencoder;

import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.*;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.streams.ReadStream;
import io.vertx.core.streams.impl.InboundBuffer;
import io.vertx.ext.mail.DKIMSignOptions;
import io.vertx.ext.mail.impl.dkim.DKIMSigner;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * This is implementation detail class. It is not intended to be used outside of this mail client.
 *
 * @author <a href="mailto: aoingl@gmail.com">Lin Gao</a>
 */
public abstract class EncodedPart {

  private static final Pattern DELIMITER = Pattern.compile("[\r\n]");

  MultiMap headers;
  String part;

  String asString() {
    StringBuilder sb = new StringBuilder(headers().toString());
    if (body() != null) {
      sb.append("\n");
      sb.append(body());
    }
    return sb.toString();
  }

  public MultiMap headers() {
    return headers;
  }

  public String body() {
    return part;
  }

  public int size() {
    return asString().length();
  }

  public ReadStream<Buffer> dkimBodyStream(Context context, DKIMSignOptions dkimOptions) {
    String[] bodyLines = null;
    return new StringLinesReadStream(context, bodyLines);
  }

  public ReadStream<Buffer> bodyStream(Context context) {
    String[] bodyLines = null;
    return new StringLinesReadStream(context, bodyLines);
  }

  public ReadStream<Buffer> stream(Context context, boolean withheaders) {
    return new EmailReadStream(context, withheaders);
  }

  public List<EncodedPart> parts() {
    return null;
  }

  public String boundary() {
    return null;
  }

  private class EmailReadStream implements ReadStream<Buffer> {
    private Handler<Void> endHandler;
    private Handler<Throwable> execeptionHandler;
    private final InboundBuffer<Buffer> pending;
    private final Context context;
    private boolean bodyReading;

    private EmailReadStream(Context context, boolean writeHeaders) {
      this.context = context;
      this.pending = new InboundBuffer<Buffer>(context)
        .emptyHandler(e -> checkEnd())
        .drainHandler(d -> readEmailBody())
        .pause();

      if (writeHeaders) {
        this.pending.write(headers().entries().stream()
          .map(entry -> Buffer.buffer(entry + "\r\n")).collect(Collectors.toList()));
        // \r\n after headers
        this.pending.write(Buffer.buffer("\r\n"));
      }
    }

    // check if it is end of the email stream
    private void checkEnd() {
      Handler<Void> handler;
      boolean ended;
      synchronized (this) {
        ended = !pending.isPaused() && pending.isEmpty() && bodyReading;
        handler = this.endHandler;
      }
      if (ended && handler != null) {
        System.out.println("call endHandler @ Thread: " + Thread.currentThread().getName());
        handleEvent(handler, null);
      }
    }

    private <T> void handleEvent(Handler<T> handler, T t) {
      if (context != Vertx.currentContext()) {
        context.runOnContext(v -> handler.handle(null));
      } else {
        handler.handle(t);
      }
    }

    private void checkException(Throwable throwable) {
      Handler<Throwable> handler;
      synchronized (this) {
        handler = this.execeptionHandler;
      }
      if (handler != null) {
        handleEvent(handler, throwable);
      }
    }

    private void readEmailBody() {
      if (context != Vertx.currentContext()) {
        context.runOnContext(v -> readEmailBody());
        return;
      }
      synchronized (this) {
        if (!bodyReading) {
          bodyReading = true;
          readBody0(context, pending).setHandler(end -> {
            if (end.succeeded()) {
              checkEnd();
            } else {
              checkException(end.cause());
            }
          });
        }
      }
    }

    @Override
    public synchronized ReadStream<Buffer> exceptionHandler(Handler<Throwable> handler) {
      pending.exceptionHandler(handler);
      this.execeptionHandler = handler;
      return this;
    }

    @Override
    public synchronized ReadStream<Buffer> handler(@Nullable Handler<Buffer> handler) {
      pending.handler(handler);
      return this;
    }

    @Override
    public synchronized ReadStream<Buffer> pause() {
      pending.pause();
      return this;
    }

    @Override
    public synchronized ReadStream<Buffer> resume() {
      pending.resume();
      readEmailBody();
      return this;
    }

    @Override
    public synchronized ReadStream<Buffer> fetch(long amount) {
      pending.fetch(amount);
      return this;
    }

    @Override
    public synchronized ReadStream<Buffer> endHandler(@Nullable Handler<Void> endHandler) {
      this.endHandler = endHandler;
      return this;
    }
  }

  // this always running on current context
  protected Future<Void> readBody0(Context context, InboundBuffer<Buffer> pending) {
    Promise<Void> promise = Promise.promise();
    try {
      List<String> bodyLines = bodyLines(body(), false, null);
      pending.write(bodyLines.stream().map(Buffer::buffer).collect(Collectors.toList()));
    } catch(Throwable t) {
      promise.fail(t);
    } finally {
      promise.complete();
    }
    return promise.future();
  }

//  private ReadStream<Buffer> headerStream(Context context) {
//    Scanner scanner = new Scanner(headers().toString() + " \n").useDelimiter(DELIMITER);
//    List<String> lines = new ArrayList<>();
//    while (scanner.hasNext()) {
//      // we can trim each header line
//      String line = scanner.nextLine().trim();
//      lines.add(line + "\r\n");
//    }
//    String[] headersArray = new String[lines.size()];
//    return new StringLinesReadStream(context, headersArray);
//  }

  private List<String> bodyLines(String body, boolean dkim, DKIMSignOptions dkimSignOptions) {
    Scanner scanner = new Scanner(body).useDelimiter(DELIMITER);
    List<String> lines = new ArrayList<>();
    while (scanner.hasNext()) {
      String line = scanner.nextLine();
      if (!dkim && line.startsWith(".")) {
        line = "." + line;
      }
      if (dkim) {
        line = DKIMSigner.processLine(line, dkimSignOptions.getBodyCanonic());
      } else {
        line += "\r\n";
      }
      lines.add(line);
    }
    return lines;
//    if (dkim) {
//      lines = lines.replaceFirst("[\r\n]*$", "\r\n");
//      if (dkimSignOptions.getBodyLimit() > 0 && dkimSignOptions.getBodyLimit() < lines.length()) {
//        lines = lines.substring(0, dkimSignOptions.getBodyLimit());
//      }
//    }
//    return lines.split("\r\n");
  }

}

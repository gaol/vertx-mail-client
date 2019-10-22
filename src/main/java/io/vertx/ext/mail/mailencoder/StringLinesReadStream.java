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

package io.vertx.ext.mail.mailencoder;

import io.vertx.codegen.annotations.Nullable;
import io.vertx.core.Context;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.streams.ReadStream;
import io.vertx.core.streams.impl.InboundBuffer;

import java.util.Objects;

/**
 *
 * @author <a href="mailto: aoingl@gmail.com">Lin Gao</a>
 */
public class StringLinesReadStream implements ReadStream<Buffer> {

  private final String[] lines;
  private int pos;
  private Handler<Void> endHandler;
  private final InboundBuffer<Buffer> pending;
  private final Context context;

  StringLinesReadStream(Context context, String[] lines) {
    Objects.requireNonNull(lines);
    this.lines = lines;
    this.context = context;
    this.pending = new InboundBuffer<Buffer>(context)
      .emptyHandler(v -> checkEnd())
      .drainHandler(v -> doRead()).pause();
  }

  private void checkEnd() {
    Handler<Void> handler;
    boolean ended;
    synchronized (this) {
      ended = pos == lines.length;
      handler = this.endHandler;
    }
    if (ended && handler != null) {
      handleInContext(handler);
    }
  }

  private void handleInContext(Handler<Void> handler) {
    if (context != Vertx.currentContext()) {
      context.runOnContext(v -> handler.handle(null));
    } else {
      handler.handle(null);
    }
  }

  private void doRead() {
    if (context != Vertx.currentContext()) {
      context.runOnContext(v -> doRead());
    } else {
      synchronized (this) {
        while(pos < this.lines.length) {
          if (!pending.write(Buffer.buffer(this.lines[pos++]))) {
            break;
          }
        }
      }
    }
    checkEnd();
  }

  @Override
  public synchronized ReadStream<Buffer> exceptionHandler(Handler<Throwable> handler) {
    pending.exceptionHandler(handler);
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
    if (!pending.resume() && pos == 0) {
      doRead();
    }
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

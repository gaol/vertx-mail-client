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
import io.vertx.core.Context;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.CaseInsensitiveHeaders;
import io.vertx.core.streams.ReadStream;
import io.vertx.core.streams.impl.InboundBuffer;

import java.util.List;
import java.util.stream.Collectors;

class MultiPart extends EncodedPart {

  private final List<EncodedPart> parts;
  private final String boundary;

  public MultiPart(List<EncodedPart> parts, String mode, String userAgent) {
    this.parts = parts;
    this.boundary = Utils.generateBoundary(userAgent);

    headers = new CaseInsensitiveHeaders();
    headers.set("Content-Type", "multipart/" + mode + "; boundary=\"" + boundary + "\"");

  }

  @Override
  String asString() {
    return partAsString(this);
  }

  private String partAsString(EncodedPart part) {
    StringBuilder sb = new StringBuilder(part.headers().toString());
    sb.append("\n");
    if (part.parts() != null) {
      for(EncodedPart thePart: part.parts()) {
        sb.append("--").append(part.boundary()).append("\n");
        sb.append(partAsString(thePart));
        sb.append("\n");
      }
    } else {
      sb.append(part.body());
    }
    return sb.toString();
  }

  @Override
  public int size() {
    int size = 0;
    for (EncodedPart part: parts) {
      size += part.size();
    }
    return size;
  }

  @Override
  public List<EncodedPart> parts() {
    return this.parts;
  }

  @Override
  public String boundary() {
    return this.boundary;
  }

  @Override
  protected Future<Void> readBody0(Context context, InboundBuffer<Buffer> pending) {
    // write each part one by one
    Promise<Void> promise = Promise.promise();
    List<ReadStream<Buffer>> partStreams = parts().stream()
      .map(p -> p.stream(context, true)).collect(Collectors.toList());
    ReadStream<Buffer> multiPartStream = new MultipartReadStream(partStreams);
    multiPartStream.pipeTo(pendingWriteStream(pending), promise);
    return promise.future();
  }

  private class MultipartReadStream implements ReadStream<Buffer> {
    private final List<ReadStream<Buffer>> partsStreams;
    private int index = -1;
    private Handler<Throwable> exceptionHandler;
    private Handler<Void> endHandler;
    private Handler<Buffer> handler;
    private final String boundaryStart;
    private final String boundaryEnd;
    private boolean started;

    private MultipartReadStream(List<ReadStream<Buffer>> partsStreams) {
      this.partsStreams = partsStreams;
      this.boundaryStart = "--" + boundary() + "\r\n";
      this.boundaryEnd = "--" + boundary() + "--\r\n";
      this.partsStreams.forEach(rs -> {
        rs.endHandler(end -> nextStream());
      });
    }

    private void nextStream() {
      synchronized (this) {
        index ++;
        System.out.println("working on stream: " + index);
        if (index < partsStreams.size()) {
          handleBoundaryStart();
          partsStreams.get(index).resume();
        } else {
          handleBoundaryEnd();
          if (endHandler != null) {
            endHandler.handle(null);
          }
        }
      }
    }

    @Override
    public synchronized ReadStream<Buffer> exceptionHandler(Handler<Throwable> handler) {
      this.exceptionHandler = handler;
      for (ReadStream<Buffer> rs: partsStreams) {
        rs.exceptionHandler(handler);
      }
      return this;
    }

    @Override
    public synchronized ReadStream<Buffer> handler(@Nullable Handler<Buffer> handler) {
      this.handler = handler;
      for (ReadStream<Buffer> rs: partsStreams) {
        rs.handler(handler);
      }
      return this;
    }

    @Override
    public synchronized ReadStream<Buffer> pause() {
      partsStreams.get(index).pause();
      return this;
    }

    private void handleBoundaryStart() {
      if (this.handler != null) {
        System.out.println("boundary start: " + boundaryStart);
        handler.handle(Buffer.buffer(boundaryStart));
      }
    }

    private void handleBoundaryEnd() {
      if (this.handler != null) {
        System.out.println("boundary end: " + boundaryEnd);
        handler.handle(Buffer.buffer(boundaryEnd));
      }
    }

    @Override
    public synchronized ReadStream<Buffer> resume() {
      if (!started) {
        handleBoundaryStart();
        partsStreams.get(0).fetch(Long.MAX_VALUE);
        started = true;
        index ++;
      }
      partsStreams.get(index).resume();
      return this;
    }

    @Override
    public synchronized ReadStream<Buffer> fetch(long amount) {
      partsStreams.get(index).fetch(amount);
      return this;
    }

    @Override
    public synchronized ReadStream<Buffer> endHandler(@Nullable Handler<Void> endHandler) {
      this.endHandler = endHandler;
      return this;
    }

  }
}

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
import io.vertx.core.http.CaseInsensitiveHeaders;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.streams.ReadStream;
import io.vertx.core.streams.WriteStream;
import io.vertx.core.streams.impl.InboundBuffer;
import io.vertx.ext.mail.DKIMSignOptions;
import io.vertx.ext.mail.MailAttachment;

import java.util.Objects;

class AttachmentPart extends EncodedPart {

  private static final Logger log = LoggerFactory.getLogger(AttachmentPart.class);

  private final MailAttachment attachment;

  AttachmentPart(MailAttachment attachment) {
    this.attachment = attachment;
    if (this.attachment.getData() == null && this.attachment.getStream() == null) {
      throw new IllegalArgumentException("Either data or stream of the attachment cannot be null");
    }
    if (this.attachment.getStream() != null && this.attachment.getSize() < 0) {
      log.warn("Size of the attachment should be specified when using stream");
    }
    headers = new CaseInsensitiveHeaders();
    String name = attachment.getName();
    String contentType;
    if (attachment.getContentType() != null) {
      contentType = attachment.getContentType();
    } else {
      contentType = "application/octet-stream";
    }
    if (name != null) {
      int index = contentType.length() + 22;
      contentType += "; name=\"" + Utils.encodeHeader(name, index) + "\"";
    }
    headers.set("Content-Type", contentType);
    headers.set("Content-Transfer-Encoding", "base64");

    if (attachment.getDescription() != null) {
      headers.set("Content-Description", attachment.getDescription());
    }
    String disposition;
    if (attachment.getDisposition() != null) {
      disposition = attachment.getDisposition();
    } else {
      disposition = "attachment";
    }
    if (name != null) {
      int index = disposition.length() + 33;
      disposition += "; filename=\"" + Utils.encodeHeader(name, index) + "\"";
    }
    headers.set("Content-Disposition", disposition);
    if (attachment.getContentId() != null) {
      headers.set("Content-ID", attachment.getContentId());
    }
    if (attachment.getHeaders() != null) {
      headers.addAll(attachment.getHeaders());
    }

    if (attachment.getData() != null) {
      part = Utils.base64(attachment.getData().getBytes());
    }
  }

  @Override
  public ReadStream<Buffer> dkimBodyStream(Context context, DKIMSignOptions dkimOptions) {
    if (body() != null) {
      return super.dkimBodyStream(context, dkimOptions);
    }
    return super.dkimBodyStream(context, dkimOptions);
  }

  @Override
  public ReadStream<Buffer> bodyStream(Context context) {
    if (body() != null) {
      return super.bodyStream(context);
    }
    ReadStream<Buffer> attachStream = this.attachment.getStream();
    if (attachStream != null) {
      return new BodyReadStream(context, attachStream);
    }
    return null;
  }

  @Override
  public int size() {
    if (attachment.getData() == null) {
      return attachment.getSize() < 0 ? 0 : (attachment.getSize() / 3) * 4;
    }
    return super.size();
  }

  @Override
  protected Future<Void> readBody0(Context context, InboundBuffer<Buffer> pending) {
    if (attachment.getData() != null) {
      return super.readBody0(context, pending);
    } else if (this.attachment.getStream() != null) {
      Promise<Void> promise = Promise.promise();
      // write the body stream to the pending buffer
      ReadStream<Buffer> attacheStream = new BodyReadStream(context, this.attachment.getStream());
      attacheStream.pipeTo(pendingWriteStream(pending), promise);
      return promise.future();
    } else {
      return Future.failedFuture("No data nor stream specified in Attachment");
    }
  }

  private WriteStream<Buffer> pendingWriteStream(final InboundBuffer<Buffer> pending) {
    return new WriteStream<Buffer>() {
      @Override
      public WriteStream<Buffer> exceptionHandler(Handler<Throwable> handler) {
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
        pending.write(data);
        if (handler != null) {
          handler.handle(Future.succeededFuture());
        }
      }

      @Override
      public void end(Handler<AsyncResult<Void>> handler) {
        // end of the stream
        if (handler != null) {
          handler.handle(Future.succeededFuture());
        }
      }

      @Override
      public WriteStream<Buffer> setWriteQueueMaxSize(int maxSize) {
        return this;
      }

      @Override
      public boolean writeQueueFull() {
        return !pending.isWritable();
      }

      @Override
      public WriteStream<Buffer> drainHandler(@Nullable Handler<Void> handler) {
        pending.drainHandler(handler);
        return this;
      }
    };
  }

  // what we need: strings line by line with CRLF as line terminator
  private class BodyReadStream implements ReadStream<Buffer> {

    private final Context context;
    private final ReadStream<Buffer> stream;

    // 57 / 3 * 4 = 76, plus CRLF is 78, which is the email line length limit.
    // see: https://tools.ietf.org/html/rfc5322#section-2.1.1
    private final int size = 57;
    private Buffer streamBuffer;
    private Handler<Buffer> handler;

    private BodyReadStream(Context context, ReadStream<Buffer> stream) {
      Objects.requireNonNull(stream, "ReadStream cannot be null");
      this.stream = stream;
      this.context = context;
      this.streamBuffer = Buffer.buffer();
    }

    @Override
    public BodyReadStream exceptionHandler(Handler<Throwable> handler) {
      if (handler != null) {
        stream.exceptionHandler(handler);
      }
      return this;
    }

    @Override
    public BodyReadStream handler(@Nullable Handler<Buffer> handler) {
      if (handler == null) {
        return this;
      }
      this.handler = handler;
      stream.handler(b -> context.runOnContext(v -> {
        Buffer buffer = streamBuffer.appendBuffer(b);
        Buffer bufferToSent = Buffer.buffer();
        int start = 0;
        while(start + size < buffer.length()) {
          final String theLine = Utils.base64(buffer.getBytes(start, start + size));
          bufferToSent.appendBuffer(Buffer.buffer(theLine + "\r\n"));
          start += size;
        }
        streamBuffer = buffer.getBuffer(start, buffer.length());
        handler.handle(bufferToSent);
      }));
      return this;
    }

    @Override
    public BodyReadStream pause() {
      stream.pause();
      return this;
    }

    @Override
    public BodyReadStream resume() {
      stream.resume();
      return this;
    }

    @Override
    public BodyReadStream fetch(long amount) {
      stream.fetch(amount);
      return this;
    }

    @Override
    public BodyReadStream endHandler(@Nullable Handler<Void> endHandler) {
      stream.endHandler(handlerInContext(v -> {
        if (streamBuffer.length() > 0 && this.handler != null) {
          String theLine = Utils.base64(streamBuffer.getBytes());
          this.handler.handle(Buffer.buffer(theLine + "\r\n"));
        }
        endHandler.handle(null);
      }));
      return this;
    }

    private Handler<Void> handlerInContext(Handler<Void> handler) {
      return vv -> context.runOnContext(handler);
    }

  }

}

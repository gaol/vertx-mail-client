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
import io.vertx.core.file.AsyncFile;
import io.vertx.core.file.OpenOptions;
import io.vertx.core.http.CaseInsensitiveHeaders;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.streams.ReadStream;
import io.vertx.ext.mail.MailAttachment;

import java.io.File;
import java.util.Objects;

class AttachmentPart extends EncodedPart {

  private static final Logger log = LoggerFactory.getLogger(AttachmentPart.class);

  // Whether to cache the ReadStream into an AsyncFile in case the Attachment's ReadStream
  // is not a re-playable stream like AsyncFile does when DKIM is enabled.
  private static final boolean CACHE_IN_FILE = Boolean.getBoolean("vertx.mail.attachment.cache.file");

  private boolean deleteAfterClose;

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
  public ReadStream<Buffer> bodyStream(Context context) {
    if (this.attachment.getStream() == null) {
      return null;
    }
    return new BodyReadStream(context, this.attachment.getStream(), false);
  }

  @Override
  public ReadStream<Buffer> dkimBodyStream(Context context) {
    if (this.attachment.getStream() == null) {
      return null;
    }
    return new BodyReadStream(context, this.attachment.getStream(), true);
  }

  @Override
  public int size() {
    if (attachment.getData() == null) {
      return attachment.getSize() < 0 ? 0 : (attachment.getSize() / 3) * 4;
    }
    return super.size();
  }

  // what we need: strings line by line with CRLF as line terminator
  private class BodyReadStream implements ReadStream<Buffer> {

    private final Context context;
    private final ReadStream<Buffer> stream;
    private Handler<Throwable> exceptionHandler;

    // if it is intended to try reset the stream after end.
    private final boolean tryReset;

    private final boolean cacheInMemory;
    private final Buffer cachedBuffer;

    private final boolean cacheInFile;
    private final String cachedFilePath;
    private AsyncFile cachedFile;
    private static final String cacheFilePrefix = "_vertx_mail_attach_";
    private static final String cachFileSuffix = "cache";

    // 57 / 3 * 4 = 76, plus CRLF is 78, which is the email line length limit.
    // see: https://tools.ietf.org/html/rfc5322#section-2.1.1
    private final int size = 57;
    private Buffer streamBuffer;
    private Handler<Buffer> handler;

    private BodyReadStream(Context context, ReadStream<Buffer> stream, boolean tryReset) {
      Objects.requireNonNull(stream, "ReadStream cannot be null");
      this.stream = stream;
      this.context = context;
      this.tryReset = tryReset;
      this.streamBuffer = Buffer.buffer();
      if (tryReset && !(this.stream instanceof AsyncFile)) {
        // cache
        if (CACHE_IN_FILE) {
          cacheInFile = true;
          cachedFilePath = context.owner().fileSystem().createTempFileBlocking(cacheFilePrefix, cachFileSuffix);
          cacheInMemory = false;
          cachedBuffer = null;
        } else {
          // cache in memory then
          cacheInFile = false;
          cachedFilePath = null;
          cacheInMemory = true;
          cachedBuffer = Buffer.buffer();
        }
      } else {
        this.cacheInMemory = false;
        this.cachedBuffer = null;
        this.cacheInFile = false;
        this.cachedFilePath = null;
      }
    }

    @Override
    public BodyReadStream exceptionHandler(Handler<Throwable> handler) {
      if (handler != null) {
        stream.exceptionHandler(handler);
        this.exceptionHandler = handler;
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
        maybeCache(bufferToSent).setHandler(r -> {
          if (r.succeeded()) {
            handler.handle(bufferToSent);
          } else {
            handleEvent(this.exceptionHandler, r.cause());
          }
        });
      }));
      return this;
    }

    private Future<Void> maybeCache(Buffer tobeCached) {
      Promise<Void> promise = Promise.promise();
      if (tryReset && tobeCached != null) {
        try {
          if (cacheInMemory) {
            cachedBuffer.appendBuffer(tobeCached);
            promise.complete();
          } else if (cacheInFile) {
            synchronized (BodyReadStream.this) {
              if (cachedFile == null) {
                context.owner().fileSystem().open(cachedFilePath, new OpenOptions().setAppend(true).setCreateNew(true))
                  .setHandler(c -> {
                    if (c.succeeded()) {
                      synchronized (BodyReadStream.this) {
                        cachedFile = c.result();
                      }
                      cachedFile.write(tobeCached, promise);
                    } else {
                      promise.fail(c.cause());
                    }
                  });
              } else {
                cachedFile.write(tobeCached, promise);
              }
            }
          } else {
            promise.complete();
          }
        } catch (Exception e) {
          promise.fail(e);
        }
      } else {
        promise.complete();
      }
      return promise.future();
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
        Buffer buffer = null;
        if (streamBuffer.length() > 0 && this.handler != null) {
          String theLine = Utils.base64(streamBuffer.getBytes());
          buffer = Buffer.buffer(theLine + "\r\n");
          this.handler.handle(buffer);
        }
        if (tryReset) {
          maybeCache(buffer).setHandler(r -> {
            if (r.succeeded()) {
              // reset AsyncFile so that it can read again
              if (attachment.getStream() instanceof AsyncFile) {
                ((AsyncFile)attachment.getStream()).setReadPos(0L);
                handleEvent(endHandler, null);
              } else {
                if (cacheInFile) {
                  // cache in an AsyncFile
                  attachment.setStream(cachedFile);
                  AttachmentPart.this.deleteAfterClose = true;
                  handleEvent(endHandler, null);
                } else {
                  // next read will be the body in memory.
                  if (part == null) {
                    part = cachedBuffer.toString();
                  }
                  handleEvent(endHandler, null);
                }
              }
            } else {
              handleEvent(this.exceptionHandler, r.cause());
            }
          });
        } else {
          // normal stream, may need to delete the cached file
          if (AttachmentPart.this.deleteAfterClose) {
            context.owner().fileSystem().delete(cachedFilePath).setHandler(deleteCacheFile -> {
              if (deleteCacheFile.succeeded()) {
                handleEvent(endHandler, null);
              } else {
                new File(cachedFilePath).deleteOnExit();
                handleEvent(this.exceptionHandler, deleteCacheFile.cause());
              }
            });
          } else {
            handleEvent(endHandler, null);
          }
        }
      }));
      return this;
    }

    private <T> void handleEvent(Handler<T> handler, T t) {
      if (handler != null) {
        handler.handle(t);
      }
    }

    private Handler<Void> handlerInContext(Handler<Void> handler) {
      return vv -> context.runOnContext(handler);
    }

  }

}

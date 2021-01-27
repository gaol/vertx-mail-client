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

import io.vertx.core.*;
import io.vertx.core.impl.ContextInternal;
import io.vertx.core.impl.NoStackTraceThrowable;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.net.NetSocket;
import io.vertx.core.net.impl.ConnectionBase;
import io.vertx.core.net.impl.clientconnection.Lease;
import io.vertx.ext.mail.MailConfig;

import java.io.IOException;
import java.util.List;

/**
 * SMTP connection to a server.
 * <p>
 * Encapsulate the NetSocket connection and the data writing/reading
 *
 * @author <a href="http://oss.lehmann.cx/">Alexander Lehmann</a>
 */
class SMTPConnection {

  private static final Logger log = LoggerFactory.getLogger(SMTPConnection.class);

  private final MailConfig config;
  private final NetSocket ns;
  private Lease<SMTPConnection> lease;
  private MultilineParser nsHandler;
  private Handler<Void> evictionHandler;

  private boolean evicted;
  private boolean socketClosed;
  private boolean shutdown;

  private Handler<String> commandReplyHandler;
  private Handler<Throwable> errorHandler;

  private Capabilities capa = new Capabilities();
  private ContextInternal context;

  SMTPConnection(MailConfig config, NetSocket ns) {
    this.config = config;
    this.ns = ns;
  }

  SMTPConnection setEvictionHandler(Handler<Void> evictionHandler) {
    this.evictionHandler = evictionHandler;
    return this;
  }

  SMTPConnection setContext(ContextInternal ctx) {
    this.context = ctx;
    return this;
  }

  SMTPConnection setLease(Lease<SMTPConnection> lease) {
    this.lease = lease;
    return this;
  }

  boolean isInitialized() {
    return this.nsHandler != null;
  }

  void init(Handler<String> initialReplyHandler) {
    if (nsHandler != null) {
      throw new IllegalStateException("SMTPConnection has been initialized.");
    }
    this.nsHandler = new MultilineParser(buffer -> {
      if (commandReplyHandler == null) {
        log.debug("dropping reply arriving after we stopped processing the buffer.");
      } else {
        // make sure we only call the handler once
        Handler<String> currentHandler = commandReplyHandler;
        commandReplyHandler = null;
        currentHandler.handle(buffer.toString());
      }
    });
    ns.exceptionHandler(this::handleNSException);
    ns.closeHandler(this::handleNSClosed);
    commandReplyHandler = initialReplyHandler;
    ns.handler(this.nsHandler);
  }

  void handleNSException(Throwable t) {
    log.debug("exceptionHandler called");
    if (!socketClosed && !shutdown) {
      shutdown();
      log.debug("got an exception on the netsocket", t);
      handleError(t);
    } else {
      log.debug("not returning follow-up exception", t);
    }
  }

  boolean isValid() {
    return !socketClosed && !shutdown;
  }

  void handleNSClosed(Void v) {
    log.debug("socket has been closed");
    socketClosed = true;
    if (!shutdown) {
      shutdown();
      handleError(new IOException("Socket closed unexpected."));
    }
    if (!evicted) {
      evicted = true;
      if (evictionHandler != null) {
        log.debug("connection got evicted by closed");
        evictionHandler.handle(null);
        cleanHandlers();
      }
    }
  }

  /**
   * @return the capabilities object
   */
  Capabilities getCapa() {
    return capa;
  }

  /**
   * parse capabilities from the ehlo reply string
   *
   * @param message the capabilities to set
   */
  void parseCapabilities(String message) {
    capa = new Capabilities();
    capa.parseCapabilities(message);
  }

  void shutdown() {
    shutdown = true;
    log.debug("Close the socket and remove it from pool");
    if (!socketClosed) {
      ns.close();
    }
    if (!evicted) {
      evicted = true;
      if (evictionHandler != null) {
        log.debug("connection got evicted on shutdown");
        evictionHandler.handle(null);
        cleanHandlers();
      }
    }
  }

  private void cleanHandlers() {
    errorHandler = null;
    commandReplyHandler = null;
  }

  void writeCommands(List<String> commands, Handler<String> resultHandler) {
    String cmds = String.join("\r\n", commands);
    this.nsHandler.setExpected(commands.size());
    this.write(cmds, r -> {
      try {
        resultHandler.handle(r);
      } finally {
        this.nsHandler.setExpected(1);
      }
    });
  }

  /*
   * write command without masking anything
   */
  void write(String str, Handler<String> commandResultHandler) {
    write(str, -1, commandResultHandler);
  }

  /*
   * write command masking everything after position blank
   */
  void write(String str, int blank, Handler<String> commandResultHandler) {
    this.commandReplyHandler = commandResultHandler;
    if (log.isDebugEnabled()) {
      String logStr;
      if (blank >= 0) {
        StringBuilder sb = new StringBuilder();
        for (int i = blank; i < str.length(); i++) {
          sb.append('*');
        }
        logStr = str.substring(0, blank) + sb;
      } else {
        logStr = str;
      }
      // avoid logging large mail body
      if (logStr.length() < 1000) {
        log.debug("command: " + logStr);
      } else {
        log.debug("command: " + logStr.substring(0, 1000) + "...");
      }
    }
    ns.write(str + "\r\n", r -> {
      if (r.failed()) {
        handleNSException(r.cause());
      }
    });
  }

  // write single line not expecting a reply, using drain handler
  void writeLineWithDrainPromise(String str, boolean mayLog, Promise<Void> promise) {
    if (mayLog) {
      log.debug(str);
    }
    if (ns.writeQueueFull()) {
      ns.drainHandler(v -> {
        // avoid getting confused by being called twice
        ns.drainHandler(null);
        ns.write(str + "\r\n").onComplete(promise);
      });
    } else {
      ns.write(str + "\r\n").onComplete(promise);
    }
  }

  private void handleError(Throwable t) {
    context.emit(t, err -> {
      Handler<Throwable> handler;
      synchronized (SMTPConnection.this) {
        handler = errorHandler;
      }
      if (handler != null) {
        handler.handle(err);
      } else {
        if (log.isDebugEnabled()) {
          log.error(t.getMessage(), t);
        } else {
          log.error(t.getMessage());
        }
      }
    });
  }

  boolean isSsl() {
    return ns.isSsl();
  }

  void upgradeToSsl(Handler<AsyncResult<Void>> handler) {
    ns.upgradeToSsl(handler);
  }

  Future<Void> returnToPool() {
    Promise<Void> promise = context.promise();
    try {
      if (config.isKeepAlive()) {
        // recycle
        log.debug("recycle for next use");
        lease.recycle();
        promise.complete(null);
      } else {
        quitCloseConnection(promise);
      }
    } catch (Exception e) {
      promise.fail(e);
    }
    return promise.future();
  }

  /**
   * send QUIT and close the connection, this operation waits for the success of the quit command but will close the
   * connection on exception as well
   */
  private void quitCloseConnection(Promise<Void> promise) {
    Promise<Void> closePromise = Promise.promise();
    closePromise.future().flatMap(v -> {
      shutdown();
      return promise.future();
    });
    writeLineWithDrainPromise("QUIT", true, closePromise);
  }

  void setErrorHandler(Handler<Throwable> newHandler) {
    errorHandler = newHandler;
  }

  /**
   * close the connection doing a QUIT command first
   */
  public void close(Promise<Void> promise) {
    quitCloseConnection(promise);
  }

  /**
   * check if a connection is already closed (this is mostly for unit tests)
   */
  boolean isClosed() {
    return socketClosed;
  }

  /**
   * get the context associated with this connection
   *
   * @return
   */
  Context getContext() {
    return context;
  }

  /**
   * Gets the underline NetSocket to the email server.
   *
   * @return the underline NetSocket
   */
  NetSocket getSocket() {
    return ns;
  }

}

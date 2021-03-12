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
import io.vertx.core.CompositeFuture;
import io.vertx.core.Context;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.impl.ContextInternal;
import io.vertx.core.impl.EventLoopContext;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.net.NetClient;
import io.vertx.core.net.NetSocket;
import io.vertx.core.net.impl.clientconnection.ConnectResult;
import io.vertx.core.net.impl.clientconnection.Endpoint;
import io.vertx.core.net.impl.clientconnection.Lease;
import io.vertx.core.net.impl.pool.ConnectionEventListener;
import io.vertx.core.net.impl.pool.ConnectionPool;
import io.vertx.core.net.impl.pool.Connector;
import io.vertx.ext.auth.PRNG;
import io.vertx.ext.mail.MailConfig;
import io.vertx.ext.mail.StartTLSOptions;
import io.vertx.ext.mail.impl.sasl.AuthOperationFactory;

import java.util.List;
import java.util.stream.Collectors;


class SMTPConnectionPool extends Endpoint<Lease<SMTPConnection>> implements Connector<SMTPConnection> {

  private static final Logger log = LoggerFactory.getLogger(SMTPConnectionPool.class);

  private final NetClient netClient;
  private final MailConfig config;
  private final PRNG prng;
  private final AuthOperationFactory authOperationFactory;
  private boolean closed = false;

  private final Vertx vertx;
  private long timerID = -1;
  private final ConnectionPool<SMTPConnection> pool;

  SMTPConnectionPool(Vertx vertx, MailConfig config) {
    super(() -> log.debug("Connection Pool disposed."));
    this.config = config;
    this.vertx = vertx;
    this.prng = new PRNG(vertx);
    this.authOperationFactory = new AuthOperationFactory(prng);

    // If the hostname verification isn't set yet, but we are configured to use SSL, update that now
    String verification = config.getHostnameVerificationAlgorithm();
    if ((verification == null || verification.isEmpty()) && !config.isTrustAll() &&
        (config.isSsl() || config.getStarttls() != StartTLSOptions.DISABLED)) {
      // we can use HTTPS verification, which matches the requirements for SMTPS
      config.setHostnameVerificationAlgorithm("HTTPS");
    }

    netClient = vertx.createNetClient(config);
    int maxSockets = config.getMaxPoolSize();
    this.pool = ConnectionPool.pool(this, maxSockets, maxSockets, -1);
    if (config.getPoolCleanerPeriod() > 0 && config.isKeepAlive() && config.getKeepAliveTimeout() > 0) {
      timerID = vertx.setTimer(config.getPoolCleanerPeriod(), this::checkExpired);
    }
  }

  private void checkExpired(long timer) {
    pool.evict(conn -> !conn.isValid(), ar -> {
      timerID = vertx.setTimer(config.getPoolCleanerPeriod(), this::checkExpired);
      if (ar.succeeded()) {
        ar.result().forEach(conn -> conn.close(Promise.promise()));
      }
    });
  }

  @Override
  public void requestConnection(ContextInternal ctx, Handler<AsyncResult<Lease<SMTPConnection>>> handler) {
    EventLoopContext eventLoopContext;
    if (ctx instanceof EventLoopContext) {
      eventLoopContext = (EventLoopContext)ctx;
    } else {
      eventLoopContext = ctx.owner().createEventLoopContext();
    }
    pool.acquire(eventLoopContext, 1, handler);
  }

  @Override
  public void connect(EventLoopContext context, ConnectionEventListener listener, Handler<AsyncResult<ConnectResult<SMTPConnection>>> handler) {
    netClient.connect(config.getPort(), config.getHostname()).onComplete(ar -> {
      if (ar.succeeded()) {
        incRefCount();
        NetSocket socket = ar.result();
        SMTPConnection connection = new SMTPConnection(config, socket)
          .setContext(context)
          .setEvictionHandler(v -> {
            decRefCount();
            listener.remove();
          });
        handler.handle(Future.succeededFuture(new ConnectResult<>(connection, 1, 1)));
      } else {
        handler.handle(Future.failedFuture(ar.cause()));
      }
    });
  }

  @Override
  public boolean isValid(SMTPConnection connection) {
    return connection.isValid();
  }

  AuthOperationFactory getAuthOperationFactory() {
    return authOperationFactory;
  }

  void getConnection(String hostname, Context ctx, Handler<AsyncResult<SMTPConnection>> resultHandler) {
    log.debug("getConnection()");
    if (closed) {
      resultHandler.handle(Future.failedFuture("connection pool is closed"));
    } else {
      ContextInternal ctxInternal = (ContextInternal)ctx;
      Promise<Lease<SMTPConnection>> promise = ctx == null ? Promise.promise() : ctxInternal.promise();
      promise.future().map(l -> l.get().setLease(l)).onComplete(cr -> {
        if (cr.succeeded()) {
          SMTPConnection conn = cr.result();
          if (conn.isInitialized()) {
            conn.reset(resultHandler);
          } else {
            SMTPStarter starter = new SMTPStarter(conn, this.config, hostname, authOperationFactory, resultHandler);
            try {
              conn.init(starter::serverGreeting);
            } catch (Exception e) {
              resultHandler.handle(Future.failedFuture(e));
            }
          }
        } else {
          resultHandler.handle(Future.failedFuture(cr.cause()));
        }
      });
      requestConnection(ctxInternal, promise);
    }
  }

  public void close() {
    close(h -> {
      super.close();
      if (h.failed()) {
        log.warn("Failed to close the pool", h.cause());
      }
      log.debug("SMTP connection pool closed.");
    });
  }

  synchronized void close(Handler<AsyncResult<Void>> finishedHandler) {
    log.debug("trying to close the connection pool");
    if (closed) {
      throw new IllegalStateException("pool is already closed");
    } else {
      closed = true;
      if (timerID >= 0) {
        vertx.cancelTimer(timerID);
        timerID = -1;
      }
      this.prng.close();
      Promise<List<Future<SMTPConnection>>> closePromise = Promise.promise();
      closePromise.future()
        .map(list -> list.stream()
          .filter(connFuture -> connFuture.succeeded() && connFuture.result().isAvailable())
          .map(connFuture -> {
            Promise<SMTPConnection> promise = Promise.promise();
            connFuture.result().close(promise);
            return promise.future();
          }).map(conn -> (Future)Future.succeededFuture())
          .collect(Collectors.toList()))
        .flatMap(CompositeFuture::join)
        .onComplete(r -> {
          if (r.succeeded()) {
            log.debug("Close the NetClient");
            if (finishedHandler != null) {
              this.netClient.close(finishedHandler);
            } else {
              this.netClient.close();
            }
          } else {
            this.netClient.close();
            if (finishedHandler != null) {
              finishedHandler.handle(Future.failedFuture(r.cause()));
            }
          }
        });
      pool.close(closePromise);
    }
  }

  int connCount() {
    return pool.size();
  }

  NetClient getNetClient() {
    return this.netClient;
  }

}

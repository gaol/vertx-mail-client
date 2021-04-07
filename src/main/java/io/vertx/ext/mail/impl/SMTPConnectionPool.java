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
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.net.NetClient;
import io.vertx.core.net.impl.clientconnection.Lease;
import io.vertx.ext.auth.PRNG;
import io.vertx.ext.mail.MailConfig;
import io.vertx.ext.mail.StartTLSOptions;
import io.vertx.ext.mail.impl.sasl.AuthOperationFactory;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

class SMTPConnectionPool {

  private static final Logger log = LoggerFactory.getLogger(SMTPConnectionPool.class);

  // max retry times if RSET failed when choosing an existed connection in pool, default to 5.
  private static final int RSET_MAX_RETRY = Integer.getInteger("vertx.mail.rset.max.retry", 5);

  private final PRNG prng;
  private final AuthOperationFactory authOperationFactory;
  private boolean closed = false;

  private final Vertx vertx;
  private final NetClient netClient;
  private final MailConfig config;
  private SMTPEndPoint endPoint;
  private long timerID = -1;

  SMTPConnectionPool(Vertx vertx, MailConfig config) {
    this.vertx = vertx;
    this.config = config;
    // If the hostname verification isn't set yet, but we are configured to use SSL, update that now
    String verification = config.getHostnameVerificationAlgorithm();
    if ((verification == null || verification.isEmpty()) && !config.isTrustAll() &&
      (config.isSsl() || config.getStarttls() != StartTLSOptions.DISABLED)) {
      // we can use HTTPS verification, which matches the requirements for SMTPS
      config.setHostnameVerificationAlgorithm("HTTPS");
    }
    netClient = vertx.createNetClient(config);
    endPoint = new SMTPEndPoint(netClient, config, this::dispose);
    this.prng = new PRNG(vertx);
    this.authOperationFactory = new AuthOperationFactory(prng);
    if (config.getPoolCleanerPeriod() > 0 && config.isKeepAlive() && config.getKeepAliveTimeout() > 0) {
      timerID = vertx.setTimer(config.getPoolCleanerPeriod(), this::checkExpired);
    }
  }

  private void checkExpired(long timer) {
    endPoint.checkExpired(ar -> {
      if (ar.succeeded()) {
        CompositeFuture.all(ar.result().stream().map(conn -> {
          Promise<Void> promise = Promise.promise();
          conn.quitCloseConnection(promise);
          return promise.future();
        }).collect(Collectors.toList()))
          .onComplete(v -> timerID = vertx.setTimer(config.getPoolCleanerPeriod(), this::checkExpired));
      }
    });
  }

  void dispose() {
    log.debug("SMTPEndPoint gets disposed.");
  }

  AuthOperationFactory getAuthOperationFactory() {
    return authOperationFactory;
  }

  void getConnection(String hostname, Handler<AsyncResult<SMTPConnection>> resultHandler) {
    getConnection(hostname, vertx.getOrCreateContext(), resultHandler);
  }

  synchronized void getConnection(String hostname, Context ctx, Handler<AsyncResult<SMTPConnection>> resultHandler) {
    getConnection0(hostname, ctx, resultHandler, 0);
  }

  private void getConnection0(String hostname, Context ctx, Handler<AsyncResult<SMTPConnection>> resultHandler, final int i) {
    log.debug("getConnection()");
    if (closed) {
      resultHandler.handle(Future.failedFuture("connection pool is closed"));
    } else {
      ContextInternal ctxInternal = (ContextInternal)ctx;
      Promise<Lease<SMTPConnection>> promise = ctxInternal.promise();
      promise.future().map(l -> l.get().setLease(l)).onComplete(cr -> {
        if (cr.succeeded()) {
          SMTPConnection conn = cr.result();
          conn.setInUse();
          if (conn.isInitialized()) {
            Promise<SMTPConnection> connReset = Promise.promise();
            connReset.future().onComplete(reset -> {
              if (reset.succeeded()) {
                resultHandler.handle(Future.succeededFuture(conn));
              } else {
                // close the conn by sending quit, and try to get another one
                Promise<Void> closePromise = Promise.promise();
                closePromise.future().onComplete(v -> {
                  if (i < RSET_MAX_RETRY) {
                    // close this one, and try get another connection
                    log.debug("Failed on RSET, try " + (i + 1) + " time");
                    getConnection0(hostname, ctx, resultHandler, i + 1);
                  } else {
                    // RSET failed more than 5 times, fail
                    resultHandler.handle(Future.failedFuture(reset.cause()));
                  }
                });
                conn.quitCloseConnection(closePromise);
              }
            });
            new SMTPReset(conn, connReset).start();
          } else {
            Promise<SMTPConnection> connInitial = Promise.promise();
            connInitial.future().onComplete(v -> {
              if (v.succeeded()) {
                resultHandler.handle(Future.succeededFuture(conn));
              } else {
                Throwable cause = v.cause();
                if (cause instanceof IOException) {
                  conn.shutdown();
                  resultHandler.handle(Future.failedFuture(cause));
                } else {
                  Promise<Void> quitPromise = Promise.promise();
                  quitPromise.future().onComplete(vv -> resultHandler.handle(Future.failedFuture(v.cause())));
                  conn.quitCloseConnection(quitPromise);
                }
              }
            });
            SMTPStarter starter = new SMTPStarter(conn, this.config, hostname, authOperationFactory, connInitial);
            try {
              conn.init(starter::serverGreeting);
            } catch (Exception e) {
              connInitial.handle(Future.failedFuture(e));
            }
          }
        } else {
          resultHandler.handle(Future.failedFuture(cr.cause()));
        }
      });
      if (!endPoint.getConnection(ctxInternal, config.getConnectTimeout(), promise)) {
        log.debug("EndPoint was disposed, create a new one");
        endPoint = new SMTPEndPoint(netClient, config, this::dispose);
        getConnection(hostname, ctx, resultHandler);
      }
    }
  }

  public void close() {
    close(h -> {
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
        .flatMap(list -> {
          List<Future> futures = list.stream()
            .filter(connFuture -> connFuture.succeeded() && connFuture.result().isAvailable())
            .map(connFuture -> {
              Promise<Void> promise = Promise.promise();
              connFuture.result().close(promise);
              return promise.future();
            })
            .collect(Collectors.toList());
          return CompositeFuture.all(futures);
        })
        .onComplete(r -> {
          log.debug("Close net client");
          if (r.succeeded()) {
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
      endPoint.close(closePromise);
    }
  }

  int connCount() {
    return endPoint.size();
  }

  NetClient getNetClient() {
    return this.netClient;
  }

}

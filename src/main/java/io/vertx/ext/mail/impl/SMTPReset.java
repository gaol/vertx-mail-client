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
import io.vertx.core.Handler;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;
import io.vertx.core.Future;

/**
 * Handle the reset command, this is mostly used to check if the connection is
 * still active
 *
 * @author <a href="http://oss.lehmann.cx/">Alexander Lehmann</a>
 */
class SMTPReset {

  private final SMTPConnection connection;
  private final Handler<AsyncResult<SMTPConnection>> handler;

  private static final Logger log = LoggerFactory.getLogger(SMTPReset.class);

  public SMTPReset(SMTPConnection connection, Handler<AsyncResult<SMTPConnection>> finishedHandler) {
    this.connection = connection;
    this.handler = finishedHandler;
  }

  public void start() {
    connection.setErrorHandler(th -> handleError("exception on RSET " + th));
    connection.write("RSET", message -> {
      log.debug("RSET result: " + message);
      if (!StatusCode.isStatusOk(message)) {
        log.warn("RSET failed: " + message);
        handleError("reset command failed: " + message);
      } else {
        finished();
      }
    });
  }

  private void finished() {
    connection.cleanHandlers();
    handler.handle(Future.succeededFuture(connection));
  }

  private void handleError(String message) {
    connection.cleanHandlers();
    handler.handle(Future.failedFuture(message));
    connection.shutdown();
  }

}
